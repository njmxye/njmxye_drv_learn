import Meting from '@meting/core';

// 只使用酷狗平台
const meting = new Meting('kugou');
meting.format(true);

async function kugouPlaylistDemo() {
  // 歌单ID
  const playlistId = '9167490';
  
  try {
    const playlistResult = await meting.playlist(playlistId);
    const songs = JSON.parse(playlistResult);
    console.log(`歌单 ${playlistId} 包含 ${songs.length} 首歌曲`);
    
    if (songs.length > 0) {
      console.log('所有歌曲:');
      songs.forEach((song, index) => {
        console.log(`  ${index + 1}. ${song.name} - ${song.artist.join(', ')}`);
      });
    }
  } catch (error) {
    console.log('获取歌单失败:', error.message);
  }
}

kugouPlaylistDemo();