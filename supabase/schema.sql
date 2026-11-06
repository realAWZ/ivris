-- ============================================================================
-- IRIS SOCIAL: PRODUCTION POSTGRESQL + SUPABASE ROW-LEVEL SECURITY SCHEMA
-- Run this entire script once in your Supabase SQL Editor:
-- https://supabase.com/dashboard/project/_/sql/new
-- ============================================================================

create extension if not exists "pgcrypto";

-- 1. PROFILES TABLE
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  handle text unique not null check (char_length(handle) between 3 and 30),
  display_name text not null,
  bio text default '',
  avatar_url text,
  account_type text not null default 'personal'
    check (account_type in ('personal', 'institution')),
  is_verified_institution boolean not null default false,
  institution_domain text,
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint valid_institution_flag check (
    (account_type = 'institution') or (is_verified_institution = false)
  )
);

-- 2. MUTUAL CONNECTIONS (FRIEND HANDSHAKE)
create table if not exists public.connections (
  id uuid primary key default gen_random_uuid(),
  requester_id uuid not null references public.profiles(id) on delete cascade,
  addressee_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'pending'
    check (status in ('pending', 'accepted', 'declined', 'blocked')),
  created_at timestamptz not null default now(),
  accepted_at timestamptz,
  constraint no_self_connection check (requester_id <> addressee_id),
  constraint unique_connection_pair unique (requester_id, addressee_id)
);

-- Helper function: Check if two users have an accepted mutual connection
create or replace function public.are_mutually_connected(user_a uuid, user_b uuid)
returns boolean
language sql
security definer
stable
as $$
  select exists (
    select 1
    from public.connections c
    where c.status = 'accepted'
      and (
        (c.requester_id = user_a and c.addressee_id = user_b)
        or
        (c.requester_id = user_b and c.addressee_id = user_a)
      )
  );
$$;

-- 3. INSTITUTION FOLLOWS & ALUMNI DIRECTORY OPT-IN
create table if not exists public.alumni_affiliations (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  institution_id uuid not null references public.profiles(id) on delete cascade,
  class_year int check (class_year between 1950 and 2040),
  role text not null default 'alumni' check (role in ('student', 'alumni', 'faculty')),
  visible_in_directory boolean not null default false,
  edu_verified boolean not null default false,
  created_at timestamptz not null default now(),
  unique (user_id, institution_id)
);

-- 4. POSTS & SHORT VIDEO STORIES
create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references public.profiles(id) on delete cascade,
  media_kind text not null check (media_kind in ('photo_post', 'video_story')),
  media_url text not null,
  media_urls jsonb not null default '[]'::jsonb,
  music jsonb default null,
  caption text default '',
  location_label text default '',
  video_duration_seconds int,
  expires_at timestamptz,
  created_at timestamptz not null default now(),

  constraint media_rules_check check (
    (
      media_kind = 'photo_post'
      and video_duration_seconds is null
      and expires_at is null
    )
    or
    (
      media_kind = 'video_story'
      and video_duration_seconds is not null
      and video_duration_seconds <= 15
      and expires_at is not null
    )
  )
);

-- 5. FINITE CATCH-UP RECEIPTS
create table if not exists public.post_receipts (
  user_id uuid not null references public.profiles(id) on delete cascade,
  post_id uuid not null references public.posts(id) on delete cascade,
  seen_at timestamptz not null default now(),
  primary key (user_id, post_id)
);

-- 6. OWNER-ONLY POST LIKES (Visible ONLY to the poster and the liker)
create table if not exists public.post_likes (
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);

-- 7. DIRECT MESSAGES BETWEEN MUTUAL FRIENDS
create table if not exists public.direct_messages (
  id uuid primary key default gen_random_uuid(),
  post_id uuid references public.posts(id) on delete set null,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  message text not null check (char_length(message) between 1 and 1000),
  created_at timestamptz not null default now()
);

-- ============================================================================
-- ROW-LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

alter table public.profiles enable row level security;
alter table public.connections enable row level security;
alter table public.alumni_affiliations enable row level security;
alter table public.posts enable row level security;
alter table public.post_receipts enable row level security;
alter table public.post_likes enable row level security;
alter table public.direct_messages enable row level security;

-- PROFILES
create policy "Profiles are searchable by authenticated users"
  on public.profiles for select to authenticated using (true);

create policy "Users can insert their own profile"
  on public.profiles for insert to authenticated with check (auth.uid() = id);

create policy "Users can update their own profile"
  on public.profiles for update to authenticated using (auth.uid() = id);

create policy "Users can delete their own profile"
  on public.profiles for delete to authenticated using (auth.uid() = id);

-- Apple Guideline 5.1.1(v) In-App Account Deletion RPC
create or replace function public.delete_own_account()
returns void
language sql
security definer
as $$
  delete from auth.users where id = auth.uid();
$$;

-- CONNECTIONS
create policy "Users can view their own connection requests and friendships"
  on public.connections for select to authenticated
  using (auth.uid() = requester_id or auth.uid() = addressee_id);

create policy "Users can send connection requests"
  on public.connections for insert to authenticated
  with check (auth.uid() = requester_id);

create policy "Addressee or requester can update connection status"
  on public.connections for update to authenticated
  using (auth.uid() = addressee_id or auth.uid() = requester_id);

-- ALUMNI AFFILIATIONS (School Follows)
create policy "Authenticated users can view school affiliations"
  on public.alumni_affiliations for select to authenticated using (true);

create policy "Users can manage their own school affiliations"
  on public.alumni_affiliations for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- POSTS PRIVACY POLICY:
-- Visible ONLY if you are the author, the author is a verified school, or you are mutually connected.
create policy "Strict mutual-connection or verified-school post visibility"
  on public.posts for select to authenticated
  using (
    author_id = auth.uid()
    or exists (
      select 1 from public.profiles p
      where p.id = posts.author_id
        and p.account_type = 'institution'
        and p.is_verified_institution = true
    )
    or public.are_mutually_connected(auth.uid(), posts.author_id)
  );

create policy "Users can insert their own posts"
  on public.posts for insert to authenticated
  with check (author_id = auth.uid());

-- POST RECEIPTS (Catch-up tracking)
create policy "Users manage their own seen receipts"
  on public.post_receipts for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- POST LIKES PRIVACY POLICY:
-- Strictly visible ONLY to the post's author (for total count) and the liker themselves.
create policy "Likes are strictly visible only to the poster and the liker"
  on public.post_likes for select to authenticated
  using (
    user_id = auth.uid()
    or exists (
      select 1 from public.posts p
      where p.id = post_likes.post_id
        and p.author_id = auth.uid()
    )
  );

create policy "Users can like visible posts"
  on public.post_likes for insert to authenticated
  with check (user_id = auth.uid());

create policy "Users can unlike their own likes"
  on public.post_likes for delete to authenticated
  using (user_id = auth.uid());

-- DIRECT MESSAGES
create policy "Users can view messages they sent or received"
  on public.direct_messages for select to authenticated
  using (auth.uid() = sender_id or auth.uid() = recipient_id);

create policy "Users can send direct messages"
  on public.direct_messages for insert to authenticated
  with check (auth.uid() = sender_id);

-- 8. INSTITUTION VERIFICATION APPLICATIONS
create table if not exists public.institution_applications (
  id uuid primary key default gen_random_uuid(),
  applicant_user_id uuid references public.profiles(id) on delete set null,
  institution_name text not null,
  official_domain text not null,
  contact_email text not null,
  notes text default '',
  status text not null default 'pending_review'
    check (status in ('pending_review', 'approved', 'declined')),
  created_at timestamptz not null default now()
);

alter table public.institution_applications enable row level security;

create policy "Anyone can submit an institution application"
  on public.institution_applications for insert
  to anon, authenticated
  with check (true);

-- STORAGE BUCKET FOR PHOTOS & SHORT VIDEOS
insert into storage.buckets (id, name, public)
values ('media', 'media', true)
on conflict (id) do nothing;

create policy "Authenticated users can upload media"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'media' and (storage.foldername(name))[1] = auth.uid()::text);

create policy "Anyone can view media URLs"
  on storage.objects for select to authenticated
  using (bucket_id = 'media');
