export type AccountType = 'personal' | 'institution';

export type ConnectionStatus = 'stranger' | 'pending_sent' | 'incoming_request' | 'accepted';

export type MediaKind = 'photo_post' | 'video_story';

export interface UserProfile {
  id: string;
  handle: string;
  displayName: string;
  subtitle: string;
  accountType: AccountType;
  isVerifiedInstitution: boolean;
  connectionStatus?: ConnectionStatus;
}

export interface VideoStory {
  id: string;
  authorId: string;
  authorHandle: string;
  initials: string;
  isInstitution: boolean;
  durationSeconds: number;
  caption: string;
  createdAtLabel: string;
}

export interface PhotoPost {
  id: string;
  authorId: string;
  authorHandle: string;
  isInstitution: boolean;
  locationLabel: string;
  caption: string;
  createdAtLabel: string;
  seen: boolean;
  likedByViewer: boolean;
  /**
   * Populated ONLY when `authorId === currentUser.id` via Supabase RLS policy
   * ("Likes are strictly visible only to the poster and the liker").
   * Always undefined on other people's posts.
   */
  ownerOnlyLikesCount?: number;
  ownerOnlyFirstLiker?: string;
}

export interface DirectMessage {
  id: string;
  from: 'me' | 'them';
  text: string;
  timeLabel: string;
}

export interface DirectThread {
  id: string;
  friendName: string;
  friendHandle: string;
  initials: string;
  statusLabel: string;
  unread: boolean;
  messages: DirectMessage[];
}
