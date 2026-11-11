import React, { useEffect, useState, useCallback } from 'react';
import {
  SafeAreaView,
  View,
  Text,
  TouchableOpacity,
  ScrollView,
  TextInput,
  StyleSheet,
  Modal,
  Image,
  ActivityIndicator,
  Alert,
  Dimensions,
  Switch,
} from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import {
  API_BASE_URL,
  getStoredToken,
  signUpUser,
  verifyEmailCode,
  signInUser,
  signOutUser,
  fetchAppState,
  createPost,
  deletePost,
  deleteUserAccount,
  updateUserSettings,
  toggleConnection,
  fetchChatMessages,
  sendChatMessage,
  markPostSeen,
  recordPostView,
  applyForInstitution,
  resolveMediaUrl,
} from './utils/api';
import { AccountType } from './src/types/models';

type ScreenKey = 'main' | 'search' | 'profile' | 'settings' | 'messages' | 'chat' | 'myPost';
type SearchTabKey = 'accounts' | 'institutions' | 'requests';

const SCREEN_WIDTH = Dimensions.get('window').width;
const GRID_SIZE = (SCREEN_WIDTH - 4) / 3;

interface MusicTrack {
  id: string;
  title: string;
  artist: string;
  artwork_url: string;
  preview_url: string;
}

interface UserSettings {
  read_receipts?: boolean;
  story_replies?: boolean;
  auto_hide_seen?: boolean;
  quiet_mode?: boolean;
  notify_requests?: boolean;
  notify_messages?: boolean;
}

interface DbProfile {
  id: string;
  email?: string;
  handle: string;
  display_name: string;
  bio: string;
  avatar_url: string | null;
  account_type: AccountType;
  is_verified_institution: boolean;
  settings?: UserSettings;
}

interface DbPost {
  id: string;
  author_id: string;
  media_kind: 'photo_post' | 'video_story';
  media_url: string;
  media_urls?: string[];
  music?: MusicTrack | null;
  caption: string;
  location_label: string;
  created_at: string;
  profiles?: DbProfile;
  likedByMe?: boolean;
  ownerOnlyLikesCount?: number;
}

interface DbConnection {
  id: string;
  requester_id: string;
  addressee_id: string;
  status: 'pending' | 'accepted' | 'declined' | 'blocked';
}

interface DbMessage {
  id: string;
  sender_id: string;
  recipient_id: string;
  message: string;
  created_at: string;
}

export default function App() {
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [confirmModalOpen, setConfirmModalOpen] = useState<boolean>(false);
  const [pendingEmail, setPendingEmail] = useState<string>('');
  const [confirmCodePreview, setConfirmCodePreview] = useState<string>('');
  const [confirmCodeInput, setConfirmCodeInput] = useState<string>('');
  const [myProfile, setMyProfile] = useState<DbProfile | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Auth Form State (All standard sign-ups are personal accounts; institutions apply for approval)
  const [isSignUp, setIsSignUp] = useState<boolean>(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [handle, setHandle] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [instApplyOpen, setInstApplyOpen] = useState<boolean>(false);
  const [instName, setInstName] = useState('');
  const [instDomain, setInstDomain] = useState('');
  const [instEmail, setInstEmail] = useState('');

  // Navigation State
  const [activeScreen, setActiveScreen] = useState<ScreenKey>('main');
  const [searchTab, setSearchTab] = useState<SearchTabKey>('accounts');
  const [activeStory, setActiveStory] = useState<DbPost | null>(null);
  const [selectedMyPost, setSelectedMyPost] = useState<DbPost | null>(null);
  const [activeChatPartner, setActiveChatPartner] = useState<DbProfile | null>(null);
  const [carouselIndexes, setCarouselIndexes] = useState<Record<string, number>>({});

  // Live Database State
  const [feedPosts, setFeedPosts] = useState<DbPost[]>([]);
  const [stories, setStories] = useState<DbPost[]>([]);
  const [myStories, setMyStories] = useState<DbPost[]>([]);
  const [myPosts, setMyPosts] = useState<DbPost[]>([]);
  const [seenPostIds, setSeenPostIds] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<DbProfile[]>([]);
  const [connections, setConnections] = useState<DbConnection[]>([]);
  const [messages, setMessages] = useState<DbMessage[]>([]);
  const [chatDraft, setChatDraft] = useState('');

  // New Post Modal & Music Picker State
  const [composeModalOpen, setComposeModalOpen] = useState(false);
  const [composeKind, setComposeKind] = useState<'photo_post' | 'video_story'>('photo_post');
  const [composeCaption, setComposeCaption] = useState('');
  const [composeLocation, setComposeLocation] = useState('');
  const [selectedMusic, setSelectedMusic] = useState<MusicTrack | null>(null);
  const [musicModalOpen, setMusicModalOpen] = useState(false);
  const [musicQuery, setMusicQuery] = useState('');
  const [musicResults, setMusicResults] = useState<MusicTrack[]>([]);
  const [uploading, setUploading] = useState(false);

  // Settings State
  const [settings, setSettings] = useState<UserSettings>({
    read_receipts: true,
    story_replies: true,
    auto_hide_seen: false,
    quiet_mode: false,
    notify_requests: true,
    notify_messages: true,
  });

  // 1. Restore persistent auth session
  useEffect(() => {
    getStoredToken().then((token) => {
      setAuthToken(token);
      setLoading(false);
    });
  }, []);

  // 2. Load Current User Profile & Real Data from Server
  const refreshAllData = useCallback(async () => {
    const token = await getStoredToken();
    if (!token) return;
    try {
      const data = await fetchAppState();
      if (data?.user) {
        setMyProfile(data.user);
        if (data.user.settings) {
          setSettings((prev) => ({ ...prev, ...data.user.settings }));
        }
        setConnections(data.connections || []);
        setSeenPostIds(data.seenPostIds || []);
        setFeedPosts(data.feedPosts || []);
        setMyPosts(data.myPosts || []);
        setStories(data.stories || []);
        setMyStories(data.myStories || []);
        setSearchResults(data.allProfiles || []);
      } else {
        await signOutUser();
        setAuthToken(null);
        setMyProfile(null);
      }
    } catch (err: any) {
      if (err?.status === 401) {
        await signOutUser();
        setAuthToken(null);
        setMyProfile(null);
      }
    }
  }, []);

  useEffect(() => {
    if (authToken) {
      refreshAllData();
    }
  }, [authToken, refreshAllData]);

  // 3. Search Global 100M+ Song Catalog (Apple Music / iTunes API)
  const searchCatalogMusic = async (query: string) => {
    const term = query.trim() || 'top hits';
    try {
      const res = await fetch(
        `https://itunes.apple.com/search?term=${encodeURIComponent(term)}&media=music&entity=song&limit=20`
      );
      const data = await res.json();
      const tracks: MusicTrack[] = (data.results || [])
        .filter((item: any) => Boolean(item.previewUrl))
        .map((item: any) => ({
          id: String(item.trackId),
          title: item.trackName || 'Unknown Track',
          artist: item.artistName || 'Unknown Artist',
          artwork_url: item.artworkUrl100 || '',
          preview_url: item.previewUrl || '',
        }));
      setMusicResults(tracks);
    } catch (_err) {
      setMusicResults([]);
    }
  };

  // 4. Sign Up / Sign In Handler with Mandatory Email Verification
  const handleAuth = async () => {
    if (!email.trim() || !password.trim()) {
      Alert.alert('Missing fields', 'Please enter your email and password.');
      return;
    }

    setLoading(true);
    try {
      if (isSignUp) {
        const cleanHandle = handle.trim().toLowerCase().replace(/[^a-z0-9_.]/g, '');
        if (cleanHandle.length < 2 || !displayName.trim()) {
          Alert.alert('Missing profile info', 'Enter a username (2+ chars) and full name.');
          setLoading(false);
          return;
        }

        const res = await signUpUser({
          email: email.trim(),
          password: password.trim(),
          handle: cleanHandle,
          displayName: displayName.trim(),
        });

        if (res.needs_confirmation) {
          setPendingEmail(res.email);
          setConfirmCodePreview(res.confirmation_code_preview || '');
          setConfirmCodeInput(res.confirmation_code_preview || '');
          setConfirmModalOpen(true);
          return;
        }
      } else {
        const res = await signInUser(email.trim(), password.trim());
        if (res.needs_confirmation) {
          setPendingEmail(res.email);
          setConfirmCodePreview(res.confirmation_code_preview || '');
          setConfirmCodeInput(res.confirmation_code_preview || '');
          setConfirmModalOpen(true);
          return;
        }
        setAuthToken(res.token);
      }
    } catch (err: any) {
      Alert.alert('Authentication Error', err.message || 'Could not authenticate');
    } finally {
      setLoading(false);
    }
  };

  const handleConfirmCode = async () => {
    if (!confirmCodeInput.trim() || !pendingEmail) return;
    setLoading(true);
    try {
      const res = await verifyEmailCode(pendingEmail, confirmCodeInput.trim());
      setConfirmModalOpen(false);
      setPendingEmail('');
      setConfirmCodeInput('');
      setConfirmCodePreview('');
      setAuthToken(res.token);
      Alert.alert('Verified!', 'Your email has been confirmed. Welcome to Ivris!');
    } catch (err: any) {
      Alert.alert('Verification Failed', err.message || 'Invalid confirmation code');
    } finally {
      setLoading(false);
    }
  };

  // 5. Pick Up to 15 Photos or 1 Short Video & Post to Ivris Unified Server
  const handlePickAndUpload = async () => {
    if (!authToken || !myProfile) return;

    const permission = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (!permission.granted) {
      Alert.alert('Permission needed', 'Allow photo library access to share photos.');
      return;
    }

    const pickerResult = await ImagePicker.launchImageLibraryAsync({
      mediaTypes:
        composeKind === 'photo_post'
          ? ImagePicker.MediaTypeOptions.Images
          : ImagePicker.MediaTypeOptions.Videos,
      allowsMultipleSelection: composeKind === 'photo_post',
      selectionLimit: composeKind === 'photo_post' ? 15 : 1,
      quality: 0.85,
      videoMaxDuration: 15,
      base64: true,
    });

    if (pickerResult.canceled || !pickerResult.assets?.length) return;
    const assets = pickerResult.assets.slice(0, 15);

    setUploading(true);
    try {
      const dataUrls: string[] = [];
      for (const asset of assets) {
        if (asset.base64) {
          const mime = composeKind === 'photo_post' ? 'image/jpeg' : 'video/mp4';
          dataUrls.push(`data:${mime};base64,${asset.base64}`);
        } else {
          const res = await fetch(asset.uri);
          const blob = await res.blob();
          const base64 = await new Promise<string>((resolve, reject) => {
            const reader = new FileReader();
            reader.onloadend = () => resolve(reader.result as string);
            reader.onerror = reject;
            reader.readAsDataURL(blob);
          });
          dataUrls.push(base64);
        }
      }

      await createPost({
        dataUrls,
        caption: composeCaption.trim(),
        location: composeLocation.trim(),
        mediaKind: composeKind,
        music: selectedMusic || null,
      });

      setComposeCaption('');
      setComposeLocation('');
      setSelectedMusic(null);
      setComposeModalOpen(false);
      await refreshAllData();
      Alert.alert('Published', composeKind === 'photo_post' ? 'Post published!' : 'Story shared!');
    } catch (err: any) {
      Alert.alert('Upload Failed', err.message || 'Could not upload media.');
    } finally {
      setUploading(false);
    }
  };

  // 6. Toggle Setting
  const handleToggleSetting = async (key: keyof UserSettings, value: boolean) => {
    const next = { ...settings, [key]: value };
    setSettings(next);
    if (authToken && myProfile) {
      try {
        await updateUserSettings(next);
      } catch (_e) {}
    }
  };

  // 7. Delete Account
  const handleDeleteAccount = () => {
    Alert.alert(
      'Delete Account',
      'Are you sure you want to permanently delete your account, photos, stories, connections, and messages? This cannot be undone.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Delete Permanently',
          style: 'destructive',
          onPress: async () => {
            if (!authToken) return;
            try {
              await deleteUserAccount();
              setAuthToken(null);
              setMyProfile(null);
              Alert.alert('Account Deleted', 'Your account and data have been removed.');
            } catch (err: any) {
              Alert.alert('Error', err.message || 'Could not delete account.');
            }
          },
        },
      ]
    );
  };

  const handleToggleLike = async (post: DbPost) => {
    await handleMarkSeen(post.id);
  };

  const handleOpenMyPost = async (post: DbPost) => {
    setSelectedMyPost(post);
    setActiveScreen('myPost');
  };

  const handleMarkSeen = async (postId: string) => {
    if (!authToken) return;
    try {
      await markPostSeen(postId);
      setSeenPostIds((prev) => [...prev, postId]);
    } catch (_e) {}
  };

  const handleConnectionAction = async (targetProfile: DbProfile) => {
    if (!authToken || !myProfile) return;
    const myId = myProfile.id;
    const existing = connections.find(
      (c) =>
        (c.requester_id === myId && c.addressee_id === targetProfile.id) ||
        (c.requester_id === targetProfile.id && c.addressee_id === myId)
    );

    const action = !existing
      ? 'request'
      : existing.status === 'pending' && existing.addressee_id === myId
      ? 'accept'
      : 'remove';

    try {
      await toggleConnection(targetProfile.id, action);
      await refreshAllData();
    } catch (err: any) {
      Alert.alert('Connection Error', err.message || 'Could not update connection');
    }
  };

  const openChatWithUser = async (partner: DbProfile) => {
    if (!authToken || !myProfile) return;
    setActiveChatPartner(partner);
    setActiveScreen('chat');
    try {
      const res = await fetchChatMessages(partner.id);
      setMessages(res.messages || []);
    } catch (_e) {}
  };

  const handleSendDirectMessage = async () => {
    if (!authToken || !myProfile || !activeChatPartner || !chatDraft.trim()) return;
    const text = chatDraft.trim();
    setChatDraft('');
    try {
      await sendChatMessage(activeChatPartner.id, text);
      const res = await fetchChatMessages(activeChatPartner.id);
      setMessages(res.messages || []);
    } catch (err: any) {
      Alert.alert('Error', err.message || 'Could not send message');
    }
  };

  const renderPostCarousel = (post: DbPost) => {
    const urls = post.media_urls && post.media_urls.length > 0 ? post.media_urls : [post.media_url];
    const idx = Math.min(carouselIndexes[post.id] || 0, urls.length - 1);
    return (
      <View style={{ position: 'relative' }}>
        <Image source={{ uri: resolveMediaUrl(urls[idx]) }} style={styles.fullBleedPhoto} resizeMode="cover" />
        {urls.length > 1 && (
          <View style={styles.carouselCounterPill}>
            <Text style={styles.carouselCounterText}>
              {idx + 1}/{urls.length}
            </Text>
          </View>
        )}
        {urls.length > 1 && (
          <View style={styles.carouselStepRow}>
            <TouchableOpacity
              style={styles.carouselStepBtn}
              onPress={() =>
                setCarouselIndexes((prev) => ({
                  ...prev,
                  [post.id]: (idx - 1 + urls.length) % urls.length,
                }))
              }
            >
              <Text style={styles.postUsername}>‹</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.carouselStepBtn}
              onPress={() =>
                setCarouselIndexes((prev) => ({
                  ...prev,
                  [post.id]: (idx + 1) % urls.length,
                }))
              }
            >
              <Text style={styles.postUsername}>›</Text>
            </TouchableOpacity>
          </View>
        )}
      </View>
    );
  };

  if (loading) {
    return (
      <SafeAreaView style={[styles.container, styles.centered]}>
        <ActivityIndicator color="#ffffff" />
      </SafeAreaView>
    );
  }

  // 1. Sign In / Sign Up Screen ("Apply for an Institution Account" shown ONLY on Sign Up)
  if (!authToken || !myProfile) {
    return (
      <SafeAreaView style={[styles.container, styles.centered]}>
        <View style={styles.authCard}>
          <Text style={[styles.brandWordmark, { textAlign: 'center', fontSize: 28 }]}>Ivris</Text>

          <TextInput
            value={email}
            onChangeText={setEmail}
            placeholder="Email address"
            placeholderTextColor="#71717a"
            autoCapitalize="none"
            keyboardType="email-address"
            style={styles.igSearchBar}
          />
          <TextInput
            value={password}
            onChangeText={setPassword}
            placeholder="Password"
            placeholderTextColor="#71717a"
            secureTextEntry
            style={styles.igSearchBar}
          />

          {isSignUp && (
            <>
              <TextInput
                value={handle}
                onChangeText={setHandle}
                placeholder="Username"
                placeholderTextColor="#71717a"
                autoCapitalize="none"
                style={styles.igSearchBar}
              />
              <TextInput
                value={displayName}
                onChangeText={setDisplayName}
                placeholder="Full Name"
                placeholderTextColor="#71717a"
                style={styles.igSearchBar}
              />
            </>
          )}

          <TouchableOpacity style={styles.primaryAuthBtn} onPress={handleAuth}>
            <Text style={styles.igFollowBtnText}>{isSignUp ? 'Sign Up' : 'Sign In'}</Text>
          </TouchableOpacity>

          <TouchableOpacity onPress={() => setIsSignUp(!isSignUp)}>
            <Text style={styles.switchAuthText}>
              {isSignUp ? 'Already have an account? Sign in' : 'Don’t have an account? Sign up'}
            </Text>
          </TouchableOpacity>

          {isSignUp && (
            <TouchableOpacity onPress={() => setInstApplyOpen(true)} style={{ marginTop: 12 }}>
              <Text style={[styles.doneText, { textAlign: 'center' }]}>
                Apply for an Institution Account
              </Text>
            </TouchableOpacity>
          )}

          <Modal visible={confirmModalOpen} transparent animationType="slide">
            <View style={[styles.storyModal, { justifyContent: 'center', padding: 24 }]}>
              <View style={[styles.authCard, { padding: 20, borderRadius: 20, width: '100%' }]}>
                <Text style={[styles.brandWordmark, { textAlign: 'center', fontSize: 24, marginBottom: 8 }]}>Confirm your email</Text>
                <Text style={{ color: '#a1a1aa', fontSize: 13, textAlign: 'center', marginBottom: 12 }}>
                  Enter the 6-digit confirmation code for {pendingEmail}
                </Text>
                {Boolean(confirmCodePreview) && (
                  <View style={{ backgroundColor: '#18181b', padding: 12, borderRadius: 12, marginBottom: 12 }}>
                    <Text style={{ color: '#71717a', fontSize: 11, textAlign: 'center' }}>Your confirmation code:</Text>
                    <Text style={{ color: '#38bdf8', fontSize: 22, fontWeight: 'bold', textAlign: 'center', letterSpacing: 4 }}>
                      {confirmCodePreview}
                    </Text>
                  </View>
                )}
                <TextInput
                  value={confirmCodeInput}
                  onChangeText={setConfirmCodeInput}
                  placeholder="6-digit code"
                  placeholderTextColor="#71717a"
                  keyboardType="number-pad"
                  maxLength={6}
                  style={[styles.igSearchBar, { textAlign: 'center', letterSpacing: 6, fontSize: 18, fontWeight: 'bold' }]}
                />
                <TouchableOpacity style={styles.primaryAuthBtn} onPress={handleConfirmCode}>
                  <Text style={styles.igFollowBtnText}>Confirm & Sign In</Text>
                </TouchableOpacity>
                <TouchableOpacity onPress={() => setConfirmModalOpen(false)} style={{ marginTop: 12 }}>
                  <Text style={[styles.switchAuthText, { textAlign: 'center' }]}>Back</Text>
                </TouchableOpacity>
              </View>
            </View>
          </Modal>

          <Modal visible={instApplyOpen} transparent animationType="slide">
            <View style={styles.storyModal}>
              <View style={styles.storyModalHeader}>
                <Text style={styles.postUsername}>Apply for Institution Account</Text>
                <TouchableOpacity onPress={() => setInstApplyOpen(false)}>
                  <Text style={styles.closeBtnText}>Cancel</Text>
                </TouchableOpacity>
              </View>
              <View style={{ gap: 12 }}>
                <Text style={styles.postLocation}>
                  Institution accounts are verified before becoming public.
                </Text>
                <TextInput
                  value={instName}
                  onChangeText={setInstName}
                  placeholder="Institution Name"
                  placeholderTextColor="#71717a"
                  style={styles.igSearchBar}
                />
                <TextInput
                  value={instDomain}
                  onChangeText={setInstDomain}
                  placeholder="Official Domain (e.g. umich.edu)"
                  placeholderTextColor="#71717a"
                  autoCapitalize="none"
                  style={styles.igSearchBar}
                />
                <TextInput
                  value={instEmail}
                  onChangeText={setInstEmail}
                  placeholder="Official Contact Email"
                  placeholderTextColor="#71717a"
                  autoCapitalize="none"
                  style={styles.igSearchBar}
                />
                <TouchableOpacity
                  style={styles.primaryAuthBtn}
                  onPress={async () => {
                    if (instName.trim() && instEmail.trim()) {
                      try {
                        await applyForInstitution({
                          name: instName.trim(),
                          domain: instDomain.trim(),
                          email: instEmail.trim(),
                        });
                        setInstApplyOpen(false);
                        Alert.alert(
                          'Application Submitted',
                          'Your institution account application has been sent for review.'
                        );
                      } catch (err: any) {
                        Alert.alert('Error', err.message || 'Could not submit application');
                      }
                    }
                  }}
                >
                  <Text style={styles.igFollowBtnText}>Submit Application</Text>
                </TouchableOpacity>
              </View>
              <View />
            </View>
          </Modal>
        </View>
      </SafeAreaView>
    );
  }

  const unseenFeed =
    settings.auto_hide_seen !== false
      ? feedPosts.filter((p) => !seenPostIds.includes(p.id))
      : feedPosts;
  const myId = myProfile.id;
  const myInitials = (myProfile?.handle || 'U').slice(0, 2).toUpperCase();

  return (
    <SafeAreaView style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        {activeScreen === 'settings' ? (
          <TouchableOpacity onPress={() => setActiveScreen('profile')}>
            <Text style={styles.headerActionText}>‹ Profile</Text>
          </TouchableOpacity>
        ) : activeScreen === 'messages' || activeScreen === 'chat' || activeScreen === 'myPost' ? (
          <TouchableOpacity
            onPress={() =>
              setActiveScreen(
                activeScreen === 'myPost'
                  ? 'profile'
                  : activeScreen === 'chat'
                  ? 'messages'
                  : 'main'
              )
            }
          >
            <Text style={styles.headerActionText}>‹ Back</Text>
          </TouchableOpacity>
        ) : (
          <Text style={styles.brandWordmark}>
            {activeScreen === 'profile' ? myProfile?.handle || 'Ivris' : 'Ivris'}
          </Text>
        )}

        {activeScreen === 'settings' ? (
          <Text style={styles.postUsername}>Settings and activity</Text>
        ) : null}

        <View style={styles.headerRight}>
          {activeScreen === 'profile' ? (
            <TouchableOpacity onPress={() => setActiveScreen('settings')}>
              <Text style={styles.headerActionText}>☰</Text>
            </TouchableOpacity>
          ) : activeScreen !== 'settings' ? (
            <>
              <TouchableOpacity
                onPress={() => {
                  setComposeKind('photo_post');
                  setComposeModalOpen(true);
                }}
              >
                <Text style={styles.headerActionText}>+ Post</Text>
              </TouchableOpacity>
              <TouchableOpacity onPress={() => setActiveScreen('messages')}>
                <Text style={styles.headerActionText}>Messages</Text>
              </TouchableOpacity>
            </>
          ) : (
            <View style={{ width: 40 }} />
          )}
        </View>
      </View>

      <ScrollView showsVerticalScrollIndicator={false}>
        {activeScreen === 'main' && (
          <View>
            {/* Always-Visible "Your story" Bubble + Friends' Stories Row */}
            <ScrollView
              horizontal
              showsHorizontalScrollIndicator={false}
              style={styles.storyTray}
              contentContainerStyle={styles.storyTrayContent}
            >
              <TouchableOpacity
                style={styles.storyItem}
                onPress={() => {
                  if (myStories.length > 0) {
                    setActiveStory(myStories[0]);
                  } else {
                    setComposeKind('video_story');
                    setComposeModalOpen(true);
                  }
                }}
              >
                <View
                  style={[
                    styles.storyRing,
                    myStories.length > 0 ? styles.friendRing : styles.inactiveRing,
                  ]}
                >
                  <View style={styles.storyAvatarInner}>
                    <Text style={styles.storyInitials}>{myInitials}</Text>
                  </View>
                </View>
                <Text style={styles.storyUsername} numberOfLines={1}>
                  Your story
                </Text>
              </TouchableOpacity>

              {stories.map((story) => (
                <TouchableOpacity
                  key={story.id}
                  style={styles.storyItem}
                  onPress={() => setActiveStory(story)}
                >
                  <View style={[styles.storyRing, styles.friendRing]}>
                    <View style={styles.storyAvatarInner}>
                      <Text style={styles.storyInitials}>
                        {(story.profiles?.handle || 'U').slice(0, 2).toUpperCase()}
                      </Text>
                    </View>
                  </View>
                  <Text style={styles.storyUsername} numberOfLines={1}>
                    {story.profiles?.handle}
                  </Text>
                </TouchableOpacity>
              ))}
            </ScrollView>

            {/* Empty / Caught-up State */}
            {unseenFeed.length === 0 ? (
              <View style={styles.emptyStateBox}>
                <Text style={styles.postUsername}>You’re all caught up</Text>
                <Text style={styles.postLocation}>
                  Connect with friends or follow institutions in Search to see new posts.
                </Text>
                <TouchableOpacity
                  style={styles.igFollowBtn}
                  onPress={() => setActiveScreen('search')}
                >
                  <Text style={styles.igFollowBtnText}>Search</Text>
                </TouchableOpacity>
              </View>
            ) : (
              unseenFeed.map((post) => (
                <View key={post.id} style={styles.postContainer}>
                  <View style={styles.postHeaderRow}>
                    <View>
                      <Text style={styles.postUsername}>{post.profiles?.handle}</Text>
                      {post.music?.title ? (
                        <Text style={styles.musicSubtitle}>
                          ♪ {post.music.artist} · {post.music.title}
                        </Text>
                      ) : Boolean(post.location_label) ? (
                        <Text style={styles.postLocation}>{post.location_label}</Text>
                      ) : null}
                    </View>
                    <TouchableOpacity onPress={() => handleMarkSeen(post.id)}>
                      <Text style={styles.doneText}>Done</Text>
                    </TouchableOpacity>
                  </View>

                  {renderPostCarousel(post)}

                  {/* Action Row: No public like count shown on other people's posts */}
                  <View style={styles.actionRow}>
                    <View style={styles.actionLeft}>
                      <TouchableOpacity onPress={() => handleToggleLike(post)}>
                        <Text
                          style={[
                            styles.actionBtnText,
                            post.likedByMe && styles.likedText,
                          ]}
                        >
                          {post.likedByMe ? 'Liked' : 'Like'}
                        </Text>
                      </TouchableOpacity>
                      {post.profiles && (
                        <TouchableOpacity onPress={() => openChatWithUser(post.profiles!)}>
                          <Text style={styles.actionBtnText}>Message</Text>
                        </TouchableOpacity>
                      )}
                    </View>
                  </View>

                  <View style={styles.captionArea}>
                    <Text style={styles.captionText}>
                      <Text style={styles.postUsername}>{post.profiles?.handle} </Text>
                      {post.caption}
                    </Text>
                  </View>
                </View>
              ))
            )}
          </View>
        )}

        {activeScreen === 'search' && (
          <View>
            <View style={styles.searchBarWrapper}>
              <TextInput
                value={searchQuery}
                onChangeText={setSearchQuery}
                placeholder="Search"
                placeholderTextColor="#71717a"
                style={styles.igSearchBar}
              />
            </View>

            <View style={styles.underlineTabRow}>
              {(['accounts', 'institutions', 'requests'] as SearchTabKey[]).map((tab) => (
                <TouchableOpacity
                  key={tab}
                  style={[
                    styles.underlineTab,
                    searchTab === tab && styles.underlineTabActive,
                  ]}
                  onPress={() => setSearchTab(tab)}
                >
                  <Text
                    style={[
                      styles.underlineTabText,
                      searchTab === tab && styles.underlineTabTextActive,
                    ]}
                  >
                    {tab === 'institutions'
                      ? 'Institutions'
                      : tab === 'accounts'
                      ? 'Accounts'
                      : 'Requests'}
                  </Text>
                </TouchableOpacity>
              ))}
            </View>

            {searchResults
              .filter((p) => {
                const matchesQuery =
                  !searchQuery.trim() ||
                  p.handle.toLowerCase().includes(searchQuery.toLowerCase()) ||
                  p.display_name.toLowerCase().includes(searchQuery.toLowerCase());
                if (!matchesQuery) return false;
                if (searchTab === 'institutions') return p.account_type === 'institution';
                if (searchTab === 'requests') {
                  return connections.some(
                    (c) =>
                      c.requester_id === p.id &&
                      c.addressee_id === myId &&
                      c.status === 'pending'
                  );
                }
                return p.account_type === 'personal';
              })
              .map((item) => {
                const conn = connections.find(
                  (c) =>
                    (c.requester_id === myId && c.addressee_id === item.id) ||
                    (c.requester_id === item.id && c.addressee_id === myId)
                );
                const btnLabel = !conn
                  ? item.account_type === 'institution'
                    ? 'Follow'
                    : 'Add'
                  : conn.status === 'accepted'
                  ? 'Connected'
                  : conn.addressee_id === myId
                  ? 'Accept'
                  : 'Requested';

                return (
                  <View key={item.id} style={styles.userRow}>
                    <View style={styles.userRowInfo}>
                      <Text style={styles.postUsername}>{item.handle}</Text>
                      <Text style={styles.postLocation}>{item.display_name}</Text>
                    </View>
                    <TouchableOpacity
                      style={styles.igFollowBtn}
                      onPress={() => handleConnectionAction(item)}
                    >
                      <Text style={styles.igFollowBtnText}>{btnLabel}</Text>
                    </TouchableOpacity>
                  </View>
                );
              })}
          </View>
        )}

        {activeScreen === 'messages' && (
          <View>
            {searchResults
              .filter((p) =>
                connections.some(
                  (c) =>
                    c.status === 'accepted' &&
                    ((c.requester_id === myId && c.addressee_id === p.id) ||
                      (c.requester_id === p.id && c.addressee_id === myId))
                )
              )
              .map((friend) => (
                <TouchableOpacity
                  key={friend.id}
                  style={styles.userRow}
                  onPress={() => openChatWithUser(friend)}
                >
                  <View style={styles.userRowInfo}>
                    <Text style={styles.postUsername}>{friend.display_name}</Text>
                    <Text style={styles.postLocation}>@{friend.handle}</Text>
                  </View>
                  <Text style={styles.sendText}>Message</Text>
                </TouchableOpacity>
              ))}
          </View>
        )}

        {activeScreen === 'chat' && activeChatPartner && (
          <View style={styles.chatContainer}>
            {messages.map((m) => (
              <View
                key={m.id}
                style={[
                  styles.messageBubble,
                  m.sender_id === myId ? styles.myBubble : styles.theirBubble,
                ]}
              >
                <Text style={styles.messageText}>{m.message}</Text>
              </View>
            ))}
            <View style={styles.chatInputRow}>
              <TextInput
                value={chatDraft}
                onChangeText={setChatDraft}
                placeholder="Message..."
                placeholderTextColor="#71717a"
                style={styles.chatInput}
              />
              <TouchableOpacity onPress={handleSendDirectMessage}>
                <Text style={styles.sendText}>Send</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}

        {activeScreen === 'profile' && (
          <View>
            <View style={styles.profileTop}>
              <View style={[styles.profileAvatarRing, styles.friendRing]}>
                <View style={styles.profileAvatarInner}>
                  <Text style={styles.profileAvatarText}>{myInitials}</Text>
                </View>
              </View>
              <View style={styles.profileStatsRow}>
                <View style={styles.statCol}>
                  <Text style={styles.statValue}>{myPosts.length}</Text>
                  <Text style={styles.statLabel}>posts</Text>
                </View>
                <View style={styles.statCol}>
                  <Text style={styles.statValue}>
                    {connections.filter((c) => c.status === 'accepted').length}
                  </Text>
                  <Text style={styles.statLabel}>friends</Text>
                </View>
              </View>
            </View>

            <View style={styles.profileBioSection}>
              <Text style={styles.postUsername}>{myProfile?.display_name}</Text>
              {Boolean(myProfile?.bio) && (
                <Text style={styles.postLocation}>{myProfile?.bio}</Text>
              )}
              <View style={styles.profileBtnRow}>
                <TouchableOpacity
                  style={styles.profileSecondaryBtn}
                  onPress={() => setActiveScreen('settings')}
                >
                  <Text style={styles.postUsername}>Settings</Text>
                </TouchableOpacity>
              </View>
            </View>

            <View style={styles.photoGrid}>
              {myPosts.map((post) => (
                <TouchableOpacity key={post.id} onPress={() => handleOpenMyPost(post)}>
                  <Image source={{ uri: resolveMediaUrl(post.media_url) }} style={styles.gridSquare} />
                </TouchableOpacity>
              ))}
            </View>
          </View>
        )}

        {/* Redesigned iOS Settings and Activity Menu */}
        {activeScreen === 'settings' && (
          <View style={styles.settingsContainer}>
            <Text style={styles.settingsSectionHeader}>Privacy & feed</Text>
            <View style={styles.settingsCard}>
              <View style={styles.settingsRow}>
                <View style={styles.settingsRowText}>
                  <Text style={styles.postUsername}>Read receipts</Text>
                  <Text style={styles.postLocation}>
                    Show friends when you’ve seen their messages
                  </Text>
                </View>
                <Switch
                  value={settings.read_receipts !== false}
                  onValueChange={(v) => handleToggleSetting('read_receipts', v)}
                  trackColor={{ false: '#27272a', true: '#0095f6' }}
                />
              </View>
              <View style={styles.settingsRow}>
                <View style={styles.settingsRowText}>
                  <Text style={styles.postUsername}>Story replies</Text>
                  <Text style={styles.postLocation}>
                    Allow mutual friends to reply to your stories
                  </Text>
                </View>
                <Switch
                  value={settings.story_replies !== false}
                  onValueChange={(v) => handleToggleSetting('story_replies', v)}
                  trackColor={{ false: '#27272a', true: '#0095f6' }}
                />
              </View>
              <View style={styles.settingsRow}>
                <View style={styles.settingsRowText}>
                  <Text style={styles.postUsername}>Hide seen posts</Text>
                  <Text style={styles.postLocation}>
                    Remove posts from Home once marked Done
                  </Text>
                </View>
                <Switch
                  value={settings.auto_hide_seen !== false}
                  onValueChange={(v) => handleToggleSetting('auto_hide_seen', v)}
                  trackColor={{ false: '#27272a', true: '#0095f6' }}
                />
              </View>
            </View>

            <Text style={styles.settingsSectionHeader}>Notifications</Text>
            <View style={styles.settingsCard}>
              <View style={styles.settingsRow}>
                <View style={styles.settingsRowText}>
                  <Text style={styles.postUsername}>Quiet mode</Text>
                  <Text style={styles.postLocation}>
                    Mute push notifications for mindful browsing
                  </Text>
                </View>
                <Switch
                  value={Boolean(settings.quiet_mode)}
                  onValueChange={(v) => handleToggleSetting('quiet_mode', v)}
                  trackColor={{ false: '#27272a', true: '#0095f6' }}
                />
              </View>
              <View style={styles.settingsRow}>
                <View style={styles.settingsRowText}>
                  <Text style={styles.postUsername}>Connection requests</Text>
                  <Text style={styles.postLocation}>
                    Alert when someone asks to connect
                  </Text>
                </View>
                <Switch
                  value={settings.notify_requests !== false}
                  onValueChange={(v) => handleToggleSetting('notify_requests', v)}
                  trackColor={{ false: '#27272a', true: '#0095f6' }}
                />
              </View>
              <View style={styles.settingsRow}>
                <View style={styles.settingsRowText}>
                  <Text style={styles.postUsername}>Direct messages</Text>
                  <Text style={styles.postLocation}>
                    Alert when a friend sends a message
                  </Text>
                </View>
                <Switch
                  value={settings.notify_messages !== false}
                  onValueChange={(v) => handleToggleSetting('notify_messages', v)}
                  trackColor={{ false: '#27272a', true: '#0095f6' }}
                />
              </View>
            </View>

            <Text style={styles.settingsSectionHeader}>Account</Text>
            <View style={styles.settingsCard}>
              <View style={styles.settingsRow}>
                <Text style={styles.postUsername}>Confirmed email</Text>
                <Text style={styles.postLocation}>{myProfile.email || myProfile.handle}</Text>
              </View>
              <TouchableOpacity
                style={styles.settingsRow}
                onPress={async () => { await signOutUser(); setAuthToken(null); setMyProfile(null); }}
              >
                <Text style={[styles.postUsername, { color: '#38bdf8' }]}>Log out</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.settingsRow} onPress={handleDeleteAccount}>
                <Text style={[styles.postUsername, { color: '#f43f5e' }]}>
                  Delete account
                </Text>
                <Text style={{ color: '#f43f5e' }}>›</Text>
              </TouchableOpacity>
            </View>
          </View>
        )}

        {/* Poster-Only Like Count View */}
        {activeScreen === 'myPost' && selectedMyPost && (
          <View style={styles.postContainer}>
            {renderPostCarousel(selectedMyPost)}
            <View style={styles.captionArea}>
              <View style={styles.ownerOnlyLikesBanner}>
                <Text style={styles.postUsername}>
                  {selectedMyPost.ownerOnlyLikesCount || 0} likes
                </Text>
                <Text style={styles.timeText}>Visible only to you</Text>
              </View>
              <Text style={styles.captionText}>{selectedMyPost.caption}</Text>
            </View>
          </View>
        )}
      </ScrollView>

      {/* New Post (Up to 15 Photos + Music) / Story Modal */}
      <Modal visible={composeModalOpen} transparent animationType="slide">
        <View style={styles.storyModal}>
          <View style={styles.storyModalHeader}>
            <Text style={styles.postUsername}>New Share</Text>
            <TouchableOpacity onPress={() => setComposeModalOpen(false)}>
              <Text style={styles.closeBtnText}>Cancel</Text>
            </TouchableOpacity>
          </View>

          <View style={styles.underlineTabRow}>
            <TouchableOpacity
              style={[
                styles.underlineTab,
                composeKind === 'photo_post' && styles.underlineTabActive,
              ]}
              onPress={() => setComposeKind('photo_post')}
            >
              <Text style={styles.underlineTabTextActive}>Feed Photos (Up to 15)</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[
                styles.underlineTab,
                composeKind === 'video_story' && styles.underlineTabActive,
              ]}
              onPress={() => setComposeKind('video_story')}
            >
              <Text style={styles.underlineTabTextActive}>24h Story</Text>
            </TouchableOpacity>
          </View>

          <View style={{ gap: 12 }}>
            {composeKind === 'photo_post' && (
              <TouchableOpacity
                style={styles.igSearchBar}
                onPress={() => {
                  setMusicModalOpen(true);
                  if (musicResults.length === 0) searchCatalogMusic('Drake');
                }}
              >
                <Text style={styles.postUsername}>
                  {selectedMusic
                    ? `♪ ${selectedMusic.title} · ${selectedMusic.artist}`
                    : '♪ Add music (Search any song ›)'}
                </Text>
              </TouchableOpacity>
            )}
            <TextInput
              value={composeLocation}
              onChangeText={setComposeLocation}
              placeholder="Location (optional)"
              placeholderTextColor="#71717a"
              style={styles.igSearchBar}
            />
            <TextInput
              value={composeCaption}
              onChangeText={setComposeCaption}
              placeholder="Write a caption..."
              placeholderTextColor="#71717a"
              style={styles.igSearchBar}
            />
            <TouchableOpacity
              style={styles.primaryAuthBtn}
              onPress={handlePickAndUpload}
              disabled={uploading}
            >
              <Text style={styles.igFollowBtnText}>
                {uploading ? 'Uploading...' : 'Select from Camera Roll & Share'}
              </Text>
            </TouchableOpacity>
          </View>
          <View />
        </View>
      </Modal>

      {/* Music Search Modal */}
      <Modal visible={musicModalOpen} transparent animationType="slide">
        <View style={styles.storyModal}>
          <View style={styles.storyModalHeader}>
            <Text style={styles.postUsername}>Add Music</Text>
            <TouchableOpacity onPress={() => setMusicModalOpen(false)}>
              <Text style={styles.closeBtnText}>Done</Text>
            </TouchableOpacity>
          </View>
          <TextInput
            value={musicQuery}
            onChangeText={(q) => {
              setMusicQuery(q);
              searchCatalogMusic(q);
            }}
            placeholder="Search any song or artist..."
            placeholderTextColor="#71717a"
            style={[styles.igSearchBar, { marginVertical: 12 }]}
          />
          <ScrollView style={{ flex: 1 }}>
            {musicResults.map((track) => (
              <TouchableOpacity
                key={track.id}
                style={styles.userRow}
                onPress={() => {
                  setSelectedMusic(track);
                  setMusicModalOpen(false);
                }}
              >
                <View style={styles.userRowInfo}>
                  <Text style={styles.postUsername}>{track.title}</Text>
                  <Text style={styles.postLocation}>{track.artist}</Text>
                </View>
                <Text style={styles.sendText}>Add</Text>
              </TouchableOpacity>
            ))}
          </ScrollView>
        </View>
      </Modal>

      {/* Bottom Navigation */}
      <View style={styles.bottomBar}>
        <TouchableOpacity onPress={() => setActiveScreen('main')}>
          <Text style={[styles.navText, activeScreen === 'main' && styles.navActive]}>
            Home
          </Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => setActiveScreen('search')}>
          <Text style={[styles.navText, activeScreen === 'search' && styles.navActive]}>
            Search
          </Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => setActiveScreen('profile')}>
          <Text
            style={[
              styles.navText,
              ['profile', 'settings', 'myPost'].includes(activeScreen) &&
                styles.navActive,
            ]}
          >
            Profile
          </Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#000000' },
  centered: { justifyContent: 'center', padding: 24 },
  authCard: { gap: 12, padding: 20 },
  primaryAuthBtn: {
    backgroundColor: '#0ea5e9',
    paddingVertical: 12,
    borderRadius: 10,
    alignItems: 'center',
    marginTop: 4,
  },
  switchAuthText: {
    color: '#0ea5e9',
    fontSize: 12,
    textAlign: 'center',
    marginTop: 8,
  },
  header: {
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 0.5,
    borderBottomColor: '#27272a',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  brandWordmark: { color: '#ffffff', fontSize: 22, fontWeight: '700' },
  headerRight: { flexDirection: 'row', gap: 16 },
  headerActionText: { color: '#ffffff', fontSize: 13, fontWeight: '600' },
  storyTray: { borderBottomWidth: 0.5, borderBottomColor: '#27272a', paddingVertical: 10 },
  storyTrayContent: { paddingHorizontal: 12, gap: 14 },
  storyItem: { alignItems: 'center', width: 68 },
  storyRing: {
    width: 64,
    height: 64,
    borderRadius: 32,
    padding: 2,
    alignItems: 'center',
    justifyContent: 'center',
  },
  friendRing: { backgroundColor: '#e1306c' },
  inactiveRing: { backgroundColor: '#27272a' },
  storyAvatarInner: {
    width: '100%',
    height: '100%',
    borderRadius: 30,
    backgroundColor: '#18181b',
    borderWidth: 2,
    borderColor: '#000000',
    alignItems: 'center',
    justifyContent: 'center',
  },
  storyInitials: { color: '#ffffff', fontWeight: '600', fontSize: 12 },
  storyUsername: { color: '#e4e4e7', fontSize: 12, marginTop: 4 },
  emptyStateBox: { padding: 36, alignItems: 'center', gap: 12 },
  postContainer: { borderBottomWidth: 0.5, borderBottomColor: '#27272a', paddingBottom: 14 },
  postHeaderRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 14,
    paddingVertical: 10,
  },
  postUsername: { color: '#ffffff', fontSize: 13, fontWeight: '600' },
  postLocation: { color: '#a1a1aa', fontSize: 12 },
  musicSubtitle: { color: '#38bdf8', fontSize: 12, marginTop: 1 },
  doneText: { color: '#a1a1aa', fontSize: 12 },
  fullBleedPhoto: { width: '100%', height: 375, backgroundColor: '#18181b' },
  carouselCounterPill: {
    position: 'absolute',
    top: 12,
    right: 12,
    backgroundColor: 'rgba(0,0,0,0.65)',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 999,
  },
  carouselCounterText: { color: '#ffffff', fontSize: 12, fontWeight: '600' },
  carouselStepRow: {
    position: 'absolute',
    top: '45%',
    left: 10,
    right: 10,
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  carouselStepBtn: {
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: 'rgba(0,0,0,0.55)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  actionRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 14,
    paddingTop: 10,
  },
  actionLeft: { flexDirection: 'row', gap: 18 },
  actionBtnText: { color: '#ffffff', fontSize: 13, fontWeight: '600' },
  likedText: { color: '#ff3040' },
  captionArea: { paddingHorizontal: 14, paddingTop: 8, gap: 4 },
  captionText: { color: '#f4f4f5', fontSize: 13, lineHeight: 18 },
  timeText: { color: '#71717a', fontSize: 12 },
  searchBarWrapper: { paddingHorizontal: 14, paddingTop: 12, paddingBottom: 8 },
  igSearchBar: {
    backgroundColor: '#18181b',
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: '#ffffff',
    fontSize: 13,
  },
  underlineTabRow: {
    flexDirection: 'row',
    borderBottomWidth: 0.5,
    borderBottomColor: '#27272a',
  },
  underlineTab: {
    flex: 1,
    paddingVertical: 10,
    alignItems: 'center',
    borderBottomWidth: 1.5,
    borderBottomColor: 'transparent',
  },
  underlineTabActive: { borderBottomColor: '#ffffff' },
  underlineTabText: { color: '#71717a', fontSize: 12, fontWeight: '600' },
  underlineTabTextActive: { color: '#ffffff', fontSize: 12, fontWeight: '600' },
  userRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 14,
    paddingVertical: 12,
    borderBottomWidth: 0.5,
    borderBottomColor: '#18181b',
  },
  userRowInfo: { flex: 1, marginRight: 12 },
  igFollowBtn: {
    backgroundColor: '#0ea5e9',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 8,
  },
  igFollowBtnText: { color: '#ffffff', fontSize: 12, fontWeight: '600' },
  chatContainer: { padding: 14, gap: 10 },
  messageBubble: { maxWidth: '75%', paddingHorizontal: 14, paddingVertical: 10, borderRadius: 18 },
  myBubble: { alignSelf: 'flex-end', backgroundColor: '#0ea5e9' },
  theirBubble: { alignSelf: 'flex-start', backgroundColor: '#18181b' },
  messageText: { color: '#ffffff', fontSize: 13 },
  chatInputRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    marginTop: 16,
  },
  chatInput: {
    flex: 1,
    backgroundColor: '#18181b',
    borderRadius: 999,
    paddingHorizontal: 14,
    paddingVertical: 10,
    color: '#ffffff',
    fontSize: 13,
  },
  sendText: { color: '#0ea5e9', fontSize: 13, fontWeight: '700' },
  profileTop: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingTop: 16,
  },
  profileAvatarRing: { width: 76, height: 76, borderRadius: 38, padding: 2 },
  profileAvatarInner: {
    flex: 1,
    borderRadius: 36,
    backgroundColor: '#18181b',
    alignItems: 'center',
    justifyContent: 'center',
  },
  profileAvatarText: { color: '#ffffff', fontSize: 18, fontWeight: '700' },
  profileStatsRow: { flexDirection: 'row', gap: 24, paddingRight: 12 },
  statCol: { alignItems: 'center' },
  statValue: { color: '#ffffff', fontSize: 15, fontWeight: '700' },
  statLabel: { color: '#a1a1aa', fontSize: 12 },
  profileBioSection: { paddingHorizontal: 16, paddingVertical: 12, gap: 6 },
  profileBtnRow: { flexDirection: 'row', gap: 8, marginTop: 6 },
  profileSecondaryBtn: {
    flex: 1,
    backgroundColor: '#18181b',
    paddingVertical: 8,
    borderRadius: 8,
    alignItems: 'center',
  },
  photoGrid: { flexDirection: 'row', flexWrap: 'wrap', gap: 2 },
  gridSquare: { width: GRID_SIZE, height: GRID_SIZE, backgroundColor: '#18181b' },
  settingsContainer: { padding: 16, gap: 10, paddingBottom: 40 },
  settingsSectionHeader: {
    color: '#a1a1aa',
    fontSize: 12,
    fontWeight: '600',
    marginTop: 8,
    paddingHorizontal: 4,
  },
  settingsCard: {
    backgroundColor: '#121212',
    borderRadius: 16,
    borderWidth: 1,
    borderColor: '#27272a',
    overflow: 'hidden',
  },
  settingsRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 16,
    paddingVertical: 14,
    borderBottomWidth: 0.5,
    borderBottomColor: '#27272a',
  },
  settingsRowText: { flex: 1, paddingRight: 12, gap: 2 },
  ownerOnlyLikesBanner: {
    backgroundColor: '#18181b',
    padding: 10,
    borderRadius: 10,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  storyModal: { flex: 1, backgroundColor: '#000000', padding: 20, justifyContent: 'space-between' },
  storyModalHeader: { flexDirection: 'row', justifyContent: 'space-between', marginTop: 24 },
  closeBtnText: { color: '#ffffff', fontSize: 13 },
  bottomBar: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    paddingVertical: 12,
    borderTopWidth: 0.5,
    borderTopColor: '#27272a',
    backgroundColor: '#000000',
  },
  navText: { color: '#71717a', fontSize: 12, fontWeight: '600' },
  navActive: { color: '#ffffff' },
});
