const LANGUAGE_STORAGE_KEY = 'syntrix-language';

const pairs = [
  ['Welcome to SYNTRIX', 'Selamat datang di SYNTRIX'],
  ['Sign in to your space', 'Masuk ke ruangmu'],
  ['Continue where your conversations left off.', 'Lanjutkan percakapanmu dari tempat terakhir.'],
  ['Sign in', 'Masuk'],
  ['Create account', 'Buat akun'],
  ['Create your SYNTRIX identity', 'Buat identitas SYNTRIX'],
  ['Choose a handle your friends can use to find you.', 'Pilih handle agar temanmu dapat menemukanmu.'],
  ['Email address', 'Alamat email'],
  ['Password', 'Kata sandi'],
  ['Display name', 'Nama tampilan'],
  ['Unique handle', 'Handle unik'],
  ['How should we call you?', 'Kamu ingin dipanggil apa?'],
  ['3–24 characters, letters, numbers, and underscore.', '3–24 karakter, huruf, angka, dan garis bawah.'],
  ['At least 8 characters', 'Minimal 8 karakter'],
  ['Your password', 'Kata sandimu'],
  ['Secured by Supabase Authentication', 'Dilindungi oleh Supabase Authentication'],
  ['DEVICE VERIFICATION', 'VERIFIKASI PERANGKAT'],
  ['Checking device…', 'Memeriksa perangkat…'],
  ['SYNTRIX is checking this device\\'s identity.', 'SYNTRIX sedang memeriksa identitas perangkat ini.'],
  ['Open SYNTRIX on a trusted device, then select', 'Buka SYNTRIX dari perangkat tepercaya, lalu pilih'],
  ['“This is me”', '“Ini aku”'],
  ['from the Security menu.', 'dari menu Keamanan.'],
  ['Selected the wrong option', 'Salah memilih opsi'],
  ['“Not me”', '“Bukan aku”'],
  ['? Sign in again using the same browser. The device will be registered again as pending and will still require approval.', '? Masuk lagi menggunakan browser yang sama. Perangkat akan didaftarkan ulang sebagai pending dan tetap memerlukan persetujuan.'],
  ['Check again', 'Periksa lagi'],
  ['Sign out', 'Keluar'],
  ['Checking device status…', 'Memeriksa status perangkat…'],
  ['Main navigation', 'Navigasi utama'],
  ['DIGITAL SIGNAL', 'SINYAL DIGITAL'],
  ['Contact', 'Kontak'],
  ['Contacts', 'Kontak'],
  ['Security', 'Keamanan'],
  ['Settings', 'Pengaturan'],
  ['Sign out of account', 'Keluar dari akun'],
  ['CONTACTS', 'DAFTAR KONTAK'],
  ['Add contact', 'Tambah kontak'],
  ['Contact directory', 'Direktori kontak'],
  ['People and conversations', 'Orang dan percakapan'],
  ['Search contacts...', 'Cari kontak...'],
  ['Contact list', 'Daftar kontak'],
  ['Contacts will appear here. Add one to get started.', 'Kontak akan muncul di sini. Tambahkan kontak untuk memulai.'],
  ['Start a conversation', 'Mulai percakapan'],
  ['Select a contact on the left to start a chat and open your real-time messaging space.', 'Pilih kontak di sebelah kiri untuk memulai chat dan membuka ruang pesan real-time.'],
  ['A PRIVATE DIGITAL SIGNAL SPACE', 'RUANG SINYAL DIGITAL PRIBADI'],
  ['Workspace', 'Ruang kerja'],
  ['Select a conversation', 'Pilih percakapan'],
  ['Choose a contact to open a real-time messaging space.', 'Pilih kontak untuk membuka ruang pesan real-time.'],
  ['Back to contact list', 'Kembali ke daftar kontak'],
  ['Offline', 'Luring'],
  ['Online', 'Daring'],
  ['Live conversation', 'Percakapan langsung'],
  ['Write a message...', 'Tulis pesan...'],
  ['Send', 'Kirim'],
  ['ACCOUNT PROTECTION', 'PERLINDUNGAN AKUN'],
  ['Monitor signed-in devices and manage the passphrase that protects your E2EE private key.', 'Pantau perangkat yang masuk dan kelola passphrase yang melindungi private key E2EE milikmu.'],
  ['A new device signed in to your account', 'Ada perangkat baru yang masuk ke akunmu'],
  ['If this was you, select "This is me". If not, select "Not me": that device will be signed out of SYNTRIX immediately. Afterward, consider changing your message key and password.', 'Kalau itu kamu, pilih "Ini aku". Jika bukan, pilih "Bukan aku": perangkat tersebut akan langsung dikeluarkan dari SYNTRIX. Setelah itu, pertimbangkan untuk mengganti kunci pesan dan kata sandi.'],
  ['This device has not been approved', 'Perangkat ini belum dikonfirmasi'],
  ['This account is also being used on another device. The account owner must select "This is me" for this device from a trusted device. If rejected, you will be signed out automatically.', 'Akun ini juga digunakan di perangkat lain. Pemilik akun harus memilih "Ini aku" untuk perangkat ini dari perangkat tepercaya. Jika ditolak, kamu akan otomatis keluar.'],
  ['Signed-in devices', 'Perangkat yang masuk'],
  ['Loading…', 'Memuat…'],
  ['End-to-end encryption', 'Enkripsi end-to-end'],
  ['Checking…', 'Memeriksa…'],
  ['Manage E2EE', 'Atur E2EE'],
  ['Private key protection', 'Perlindungan private key'],
  ['The ECDH key pair is generated in your browser. The private key is wrapped with AES-GCM using a key derived from your passphrase with PBKDF2, then the encrypted backup is stored on the server. Your passphrase and plaintext private key are never sent to Supabase.', 'Pasangan kunci ECDH dibuat di browser. Private key dibungkus AES-GCM menggunakan kunci yang diturunkan dari passphrase dengan PBKDF2, lalu backup terenkripsi disimpan di server. Passphrase dan private key dalam bentuk asli tidak pernah dikirim ke Supabase.'],
  ['ACCOUNT PREFERENCES', 'PREFERENSI AKUN'],
  ['SYNTRIX User', 'Pengguna SYNTRIX'],
  ['Dark mode', 'Mode gelap'],
  ['Enjoy a darker interface that is easier on the eyes during long sessions.', 'Gunakan tampilan gelap yang lebih nyaman untuk sesi panjang.'],
  ['Enable dark mode', 'Aktifkan mode gelap'],
  ['Light', 'Terang'],
  ['Dark', 'Gelap'],
  ['Language', 'Bahasa'],
  ['Choose the language used throughout SYNTRIX.', 'Pilih bahasa yang digunakan di seluruh SYNTRIX.'],
  ['Interface language', 'Bahasa antarmuka'],
  ['About SYNTRIX', 'Tentang SYNTRIX'],
  ['A digital data communication learning space.', 'Ruang belajar komunikasi data digital.'],
  ['Delete account', 'Hapus akun'],
  ['Permanently delete your SYNTRIX account and all its data. This action cannot be undone.', 'Hapus akun dan seluruh data SYNTRIX secara permanen. Tindakan ini tidak dapat dibatalkan.'],
  ['New connection', 'Koneksi baru'],
  ['Enter the unique SYNTRIX handle of the person you want to talk to.', 'Masukkan handle SYNTRIX unik dari orang yang ingin kamu ajak bicara.'],
  ['Contact handle', 'Handle kontak'],
  ['Cancel', 'Batal'],
  ['KONFIRMASI PERANGKAT', 'DEVICE APPROVAL'],
  ['Are you sure this device belongs to you?', 'Yakin perangkat ini milikmu?'],
  ['Make sure you recognize this device before approving it. Once approved, it will have access to your SYNTRIX account.', 'Pastikan kamu mengenali perangkat ini sebelum menyetujuinya. Setelah disetujui, perangkat tersebut akan mendapat akses ke akun SYNTRIX.'],
  ['New device', 'Perangkat baru'],
  ['Yes, this is my device', 'Ya, ini perangkat saya'],
  ['Enable E2EE', 'Aktifkan E2EE'],
  ['Your passphrase is used on this device to create a wrapping key for your private key. Keep it safe: the server cannot recover your passphrase or read your messages.', 'Passphrase digunakan di perangkat untuk membuat kunci pembungkus private key. Simpan baik-baik: server tidak dapat memulihkan passphrase atau membaca pesanmu.'],
  ['Old unlock key', 'Kunci pembuka lama'],
  ['New E2EE passphrase', 'Passphrase E2EE baru'],
  ['Enter your old key or passphrase', 'Masukkan kunci atau passphrase lama'],
  ['At least 12 characters', 'Minimal 12 karakter'],
  ['Confirm passphrase', 'Konfirmasi passphrase'],
  ['E2EE VERIFICATION', 'VERIFIKASI E2EE'],
  ['Unlock E2EE', 'Buka E2EE'],
  ['Enter your passphrase to unlock the private key on this device. The passphrase is never sent to the server.', 'Masukkan passphrase untuk membuka private key di perangkat ini. Passphrase tidak dikirim ke server.'],
  ['E2EE passphrase', 'Passphrase E2EE'],
  ['Your E2EE passphrase', 'Passphrase E2EE kamu'],
  ['Later', 'Nanti'],
  ['Unlock private key', 'Buka private key'],
  ['PERMANENT ACTION', 'TINDAKAN PERMANEN'],
  ['Delete your SYNTRIX account?', 'Hapus akun SYNTRIX?'],
  ['All profiles, contacts, messages, E2EE identities, and registered devices will be permanently deleted. Type', 'Seluruh profil, daftar kontak, pesan, identitas E2EE, dan perangkat terdaftar akan dihapus permanen. Ketik'],
  ['DELETE ACCOUNT', 'HAPUS AKUN'],
  ['to continue.', 'untuk melanjutkan.'],
  ['Confirmation', 'Konfirmasi'],
  ['Delete permanently', 'Hapus permanen'],
  ['Transmission analysis', 'ANALISIS TRANSMISI'],
  ['Signal inspector', 'Pemeriksa sinyal'],
  ['Close inspector', 'Tutup pemeriksa'],
  ['Something went wrong. Please try again.', 'Terjadi kesalahan. Silakan coba lagi.'],
  ['The email or password is incorrect.', 'Email atau password tidak cocok.'],
  ['Your email has not been confirmed. Check your inbox.', 'Email belum dikonfirmasi. Periksa kotak masuk email kamu.'],
  ['This email is already registered. Please sign in.', 'Email ini sudah terdaftar. Silakan masuk.'],
  ['That handle is already in use. Choose another one.', 'Handle tersebut sudah digunakan. Pilih handle lain.'],
  ['Too many attempts. Please try again later.', 'Terlalu banyak percobaan. Coba lagi nanti.'],
  ['Registration failed. Try another handle.', 'Pendaftaran gagal. Coba handle lain.'],
  ['Unable to connect to the server. Check your internet connection and Supabase configuration.', 'Tidak dapat terhubung ke server. Periksa internet dan konfigurasi Supabase.'],
  ['That handle was not found. Make sure it is correct.', 'Handle tersebut tidak ditemukan. Pastikan handle yang dimasukkan benar.'],
  ['You cannot add your own account.', 'Kamu tidak bisa menambahkan akun sendiri.'],
  ['Enable your account\\'s E2EE key before sending a message.', 'Aktifkan kunci E2EE akunmu sebelum mengirim pesan.'],
  ['The recipient has not created an E2EE key, so the message cannot be sent yet.', 'Pengguna tujuan belum membuat kunci E2EE, jadi pesan belum dapat dikirim.'],
  ['Database access was denied. Check the Supabase migrations and RLS policies.', 'Akses database ditolak. Periksa migration dan kebijakan RLS Supabase.'],
  ['This device has not been verified, so it cannot manage other devices yet.', 'Perangkat ini belum dikonfirmasi sebagai milikmu, jadi belum bisa mengelola perangkat lain.'],
  ['This device has not been approved. Wait for approval from a trusted device.', 'Perangkat ini belum disetujui. Tunggu konfirmasi dari perangkat yang sudah dikenal.'],
  ['The device identity has changed. Sign out, then sign in again from this browser.', 'Identitas perangkat berubah. Keluar, lalu masuk kembali dari browser ini.'],
  ['This session was signed out from another device.', 'Sesi ini sudah dikeluarkan dari perangkat lain.'],
  ['Too many devices are registered to this account. Remove devices you no longer use.', 'Terlalu banyak perangkat tercatat di akun ini. Keluarkan perangkat yang tidak dipakai.'],
  ['The device you are using cannot be removed here. Use the Sign out button instead.', 'Perangkat yang sedang kamu pakai tidak bisa dikeluarkan dari sini. Gunakan tombol Keluar.'],
  ['Messages must be encrypted. Enable and unlock E2EE first.', 'Pesan harus dienkripsi. Aktifkan dan buka E2EE terlebih dahulu.'],
  ['This contact has not enabled E2EE. Ask them to enable it before sending a message.', 'Kontak ini belum mengaktifkan E2EE. Minta kontak mengaktifkannya sebelum mengirim pesan.'],
  ['E2EE has not been enabled for this account.', 'E2EE belum diaktifkan di akun ini.'],
  ['This message has been deleted from the conversation.', 'Pesan sudah dihapus dari percakapan.'],
  ['Incorrect passphrase.', 'Passphrase salah.'],
  ['Signed in successfully. Preparing your chat...', 'Berhasil masuk. Menyiapkan ruang chat...'],
  ['Sign-in failed.', 'Login gagal.'],
  ['Display name must contain 1–60 characters.', 'Nama tampilan harus berisi 1–60 karakter.'],
  ['Account created successfully.', 'Akun berhasil dibuat.'],
  ['Account created. Check your email to confirm your address before signing in.', 'Akun dibuat. Periksa email untuk mengonfirmasi alamat email sebelum masuk.'],
  ['Registration failed.', 'Registrasi gagal.'],
  ['Not active. Enable E2EE to start sending messages.', 'Belum aktif. Aktifkan E2EE untuk mulai mengirim pesan.'],
  ['Enabled and unlocked on this device. The private key remains encrypted on the server.', 'Aktif dan terbuka di perangkat ini. Private key tetap terenkripsi di server.'],
  ['Enabled, but locked on this device. Unlock it with your E2EE passphrase.', 'Aktif, tetapi terkunci di perangkat ini. Buka dengan passphrase E2EE.'],
  ['Message', 'Pesan'],
  ['Show message', 'Tampilkan pesan'],
  ['Show signal', 'Tampilkan sinyal'],
  ['Message not revealed yet', 'Pesan belum ditampilkan'],
  ['Delete message for both participants', 'Hapus pesan untuk kedua pihak'],
  ['Delete message', 'Hapus pesan'],
  ['Read', 'Dibaca'],
  ['Enter your E2EE passphrase to unlock this message.', 'Masukkan passphrase E2EE untuk membuka pesan ini.'],
  ['Message payload was not found.', 'Payload pesan tidak ditemukan.'],
  ['The contact\\'s public key was not found.', 'Kunci publik kontak tidak ditemukan.'],
  ['Unlock this message only with your E2EE passphrase. Other messages will remain hidden.', 'Masukkan passphrase E2EE untuk membuka pesan ini saja. Pesan lain tetap tersembunyi.'],
  ['Enter your passphrase to unlock the private key on this device.', 'Masukkan passphrase untuk membuka private key di perangkat ini.'],
  ['New device signed in: ', 'Perangkat baru masuk: '],
  ['Open Security to review it.', 'Buka menu Keamanan untuk memeriksanya.'],
  ['This device', 'Perangkat ini'],
  ['Not approved', 'Belum dikonfirmasi'],
  ['Trusted', 'Dikenal'],
  ['Approximate', 'perkiraan'],
  ['Unknown location', 'Lokasi tidak diketahui'],
  ['Computer / laptop', 'Komputer / laptop'],
  ['Phone', 'Ponsel'],
  ['Device', 'Perangkat'],
  ['Location', 'Lokasi'],
  ['IP address', 'Alamat IP'],
  ['Signed in at', 'Login pada'],
  ['Last active', 'Terakhir aktif'],
  ['Device type', 'Jenis perangkat'],
  ['Browser', 'Browser'],
  ['Operating system', 'Sistem operasi'],
  ['Time zone', 'Zona waktu'],
  ['First seen', 'Pertama terlihat'],
  ['This is me', 'Ini aku'],
  ['Not me', 'Bukan aku'],
  ['Remove device', 'Keluarkan perangkat'],
  ['Check device approval first', 'Konfirmasi perangkat dulu'],
  ['Sign-in succeeded, but this device has not been approved. Profile, contacts, messages, and the private key remain locked.', 'Login berhasil, tetapi perangkat ini belum disetujui. Data profil, kontak, pesan, dan private key tetap terkunci.'],
  ['Status: waiting for approval from a trusted device.', 'Status: menunggu persetujuan dari perangkat yang sudah dikenal.'],
  ['Unable to load the workspace.', 'Tidak dapat memuat workspace.'],
  ['This session was signed out from another device. Please sign in again.', 'Sesi ini dikeluarkan dari perangkat lain. Silakan masuk lagi.'],
  ['This browser does not save a persistent device identity. Your next sign-in may be detected as a new device.', 'Browser ini tidak menyimpan identitas perangkat. Login berikutnya mungkin terbaca sebagai perangkat baru.'],
  ['Sign-in succeeded, but the device could not be registered. Check your connection and reload the page.', 'Login berhasil, tetapi perangkat belum berhasil dicatat. Periksa koneksi lalu muat ulang halaman.'],
  ['Checking…', 'Memeriksa…'],
  ['Unable to sign out of the account.', 'Gagal keluar dari akun.'],
  ['Are you sure you want to remove this device from your account? Its session will end immediately.', 'Keluarkan perangkat ini dari akunmu? Sesinya akan langsung berakhir.'],
  ['That device was signed out immediately. Consider changing your message key and password.', 'Perangkat itu langsung dikeluarkan. Sebaiknya ganti kunci pesan dan password.'],
  ['That device is no longer available.', 'Perangkat itu sudah tidak ada.'],
  ['Unable to process the device.', 'Gagal memproses perangkat.'],
  ['Approving...', 'Menyetujui...'],
  ['Okay, that device is now marked as yours.', 'Oke, perangkat itu ditandai sebagai kamu.'],
  ['That device has already been processed.', 'Perangkat itu sudah diproses.'],
  ['Unable to approve the device.', 'Gagal menyetujui perangkat.'],
  ['Unable to check the device.', 'Tidak dapat memeriksa perangkat.'],
  ['Unable to check the sign-in session.', 'Gagal memeriksa sesi login.'],
  ['Invalid handle format.', 'Format handle tidak valid.'],
  ['Looking up...', 'Mencari...'],
  ['That handle was not found.', 'Handle tersebut tidak ditemukan.'],
  ['Unable to add the contact.', 'Tidak bisa menambahkan kontak.'],
  ['Please select a contact first.', 'Pilih kontak terlebih dahulu.'],
  ['Enable E2EE before sending a message.', 'Aktifkan E2EE terlebih dahulu sebelum mengirim pesan.'],
  ['Unlock E2EE on this device before sending a message.', 'Buka E2EE di perangkat ini sebelum mengirim pesan.'],
  ['This contact has not enabled E2EE. Message delivery is blocked.', 'Kontak ini belum mengaktifkan E2EE. Pengiriman pesan belum diizinkan.'],
  ['The message could not be encrypted or sent.', 'Pesan gagal dienkripsi atau dikirim.'],
  ['Unlocking message...', 'Membuka pesan...'],
  ['Unlocking private key...', 'Membuka private key...'],
  ['Message unlocked successfully.', 'Pesan berhasil dibuka.'],
  ['E2EE unlocked on this device.', 'E2EE berhasil dibuka di perangkat ini.'],
  ['The passphrase is incorrect or the message could not be unlocked.', 'Passphrase salah atau pesan tidak dapat dibuka.'],
  ['Unable to unlock E2EE.', 'Gagal membuka E2EE.'],
  ['Passphrase confirmation does not match.', 'Konfirmasi passphrase tidak cocok.'],
  ['The new E2EE passphrase must be at least 12 characters and no more than 256 bytes.', 'Passphrase E2EE baru minimal 12 karakter dan maksimal 256 byte.'],
  ['Enter your old unlock key to verify your account.', 'Masukkan kunci pembuka lama untuk memverifikasi akun.'],
  ['Enter your current E2EE passphrase.', 'Masukkan passphrase E2EE saat ini.'],
  ['Enabling E2EE...', 'Mengaktifkan E2EE...'],
  ['Changing passphrase...', 'Mengganti passphrase...'],
  ['E2EE enabled successfully.', 'E2EE berhasil diaktifkan.'],
  ['E2EE passphrase changed successfully.', 'Passphrase E2EE berhasil diganti.'],
  ['Unable to save E2EE settings.', 'Pengaturan E2EE gagal disimpan.'],
  ['Unlock E2EE before changing the passphrase.', 'Buka E2EE terlebih dahulu sebelum mengganti passphrase.'],
  ['Change E2EE passphrase', 'Ganti passphrase E2EE'],
  ['Deleting account...', 'Menghapus akun...'],
  ['The account could not be deleted.', 'Akun tidak berhasil dihapus.'],
  ['Unable to delete the account.', 'Akun gagal dihapus.'],
  ['Unable to sign out.', 'Gagal keluar.'],
  ['Unlock the message before opening the inspector.', 'Buka kunci pesan terlebih dahulu.'],
  ['Invalid frame: ', 'Frame tidak valid: '],
  ['Delete this message for both participants? It will be permanently removed from the conversation.', 'Hapus pesan ini untuk kedua pihak? Pesan akan dihapus permanen dari percakapan.'],
  ['Message deleted for both participants.', 'Pesan dihapus untuk kedua pihak.'],
  ['This message is no longer available.', 'Pesan sudah tidak tersedia.'],
  ['Unable to delete the message.', 'Pesan gagal dihapus.'],
  ['just now', 'baru saja'],
  ['Active now', 'Sedang aktif sekarang'],
  ['Message deleted', 'Pesan dihapus'],
  ['Message sent', 'Pesan terkirim'],
  ['You', 'Kamu'],
  ['Start bit', 'Bit awal'],
  ['Data bits', 'Bit data'],
  ['Even parity', 'Paritas genap'],
  ['Stop bit', 'Bit akhir'],
  ['Decoded message', 'Pesan hasil dekode'],
  ['Transmission format', 'Format transmisi'],
  ['NRZ-I waveform', 'Gelombang NRZ-I'],
  ['Hexadecimal bytes', 'Byte heksadesimal'],
  ['ASCII binary · 7 bit per character', 'Biner ASCII · 7 bit per karakter'],
  ['Framed binary · 10 bit per character', 'Biner berbingkai · 10 bit per karakter'],
  ['NRZ-I signal levels · HIGH / LOW', 'Level sinyal NRZ-I · HIGH / LOW'],
  ['Frame breakdown', 'Rincian frame'],
  ['Validation result', 'Hasil validasi'],
  ['Characters', 'Karakter'],
  ['Signal bits', 'Bit sinyal'],
  ['Hex bytes', 'Byte heksadesimal'],
  ['Frame size', 'Ukuran frame'],
  ['Each printable ASCII character uses one 10-bit frame: start bit ', 'Setiap karakter ASCII yang dapat dicetak menggunakan satu frame 10-bit: bit awal '],
  ['Waveform preview shows the first 120 frames to keep the browser responsive.', 'Pratinjau gelombang menampilkan 120 frame pertama agar browser tetap responsif.'],
  ['Complete waveform for this message.', 'Gelombang lengkap untuk pesan ini.'],
  ['One hexadecimal byte for each printable ASCII character.', 'Satu byte heksadesimal untuk setiap karakter ASCII yang dapat dicetak.'],
  ['Showing the first 120 characters; the complete list is available in the frame table.', 'Menampilkan 120 karakter pertama; daftar lengkap tersedia di tabel frame.'],
  ['Each frame = start bit + 7 data bits + even parity + stop bit.', 'Setiap frame = bit awal + 7 bit data + paritas genap + bit akhir.'],
  ['H = HIGH and L = LOW. A transmitted 1 changes the level; a 0 keeps it.', 'H = HIGH dan L = LOW. Bit 1 mengubah level; bit 0 mempertahankan level.']
];

const english = new Map(pairs.map(([en, id]) => [id, en]));
const indonesian = new Map(pairs);

let language = 'en';
let initialized = false;
const textState = new WeakMap();
const attributeState = new WeakMap();
const translatableAttributes = ['aria-label', 'title', 'placeholder', 'alt'];
let observer = null;
let nativeConfirm = null;

function readLanguage() {
  try {
    return localStorage.getItem(LANGUAGE_STORAGE_KEY) === 'id' ? 'id' : 'en';
  } catch {
    return 'en';
  }
}

function translateDynamic(value, target) {
  let match;
  if (target === 'en') {
    match = value.match(/^Ada (\d+) perangkat baru masuk ke akunmu$/);
    if (match) return match[1] + (match[1] === '1' ? ' new device signed in to your account' : ' new devices signed in to your account');
    match = value.match(/^Perangkat baru masuk: (.+)\. Buka menu Keamanan untuk memeriksanya\.$/);
    if (match) return 'New device signed in: ' + match[1] + '. Open Security to review it.';
    match = value.match(/^(\d+) perangkat tercatat$/);
    if (match) return match[1] + (match[1] === '1' ? ' device registered' : ' devices registered');
    match = value.match(/^Login (.+)$/);
    if (match) return 'Signed in ' + match[1];
    match = value.match(/^(.+) \(perkiraan\)$/);
    if (match) return match[1] + ' (approximate)';
    match = value.match(/^Frame tidak valid: (.+)$/);
    if (match) return 'Invalid frame: ' + match[1];
  } else {
    match = value.match(/^(\d+) new devices? signed in to your account$/);
    if (match) return match[1] + ' perangkat baru masuk ke akunmu';
    match = value.match(/^New device signed in: (.+)\. Open Security to review it\.$/);
    if (match) return 'Perangkat baru masuk: ' + match[1] + '. Buka menu Keamanan untuk memeriksanya.';
    match = value.match(/^(\d+) devices registered$/);
    if (match) return match[1] + ' perangkat tercatat';
    match = value.match(/^Signed in (.+)$/);
    if (match) return 'Login ' + match[1];
    match = value.match(/^(.+) \(approximate\)$/);
    if (match) return match[1] + ' (perkiraan)';
    match = value.match(/^Invalid frame: (.+)$/);
    if (match) return 'Frame tidak valid: ' + match[1];
  }
  return value;
}

function translateValue(value, target = language) {
  const dictionary = target === 'id' ? indonesian : english;
  return dictionary.get(value) ?? translateDynamic(value, target);
}

function applyText(node) {
  const parent = node.parentElement;
  if (!parent || parent.closest('script, style, code, pre, textarea')) return;

  let record = textState.get(node);
  if (!record || node.nodeValue !== record.rendered) {
    record = { source: node.nodeValue, rendered: node.nodeValue };
    textState.set(node, record);
  }

  const raw = record.source;
  const leading = raw.match(/^\s*/)?.[0] ?? '';
  const trailing = raw.match(/\s*$/)?.[0] ?? '';
  const core = raw.slice(leading.length, raw.length - trailing.length);
  const translated = core ? leading + translateValue(core) + trailing : raw;
  if (node.nodeValue !== translated) node.nodeValue = translated;
  record.rendered = translated;
}

function applyAttribute(element, name) {
  const current = element.getAttribute(name);
  if (current === null) return;

  let records = attributeState.get(element);
  if (!records) {
    records = new Map();
    attributeState.set(element, records);
  }
  let record = records.get(name);
  if (!record || current !== record.rendered) {
    record = { source: current, rendered: current };
    records.set(name, record);
  }

  const translated = translateValue(record.source);
  if (current !== translated) element.setAttribute(name, translated);
  record.rendered = translated;
}

function applySubtree(root) {
  if (!root) return;
  if (root.nodeType === Node.TEXT_NODE) {
    applyText(root);
    return;
  }
  if (root.nodeType !== Node.ELEMENT_NODE && root !== document.body) return;

  const elements = [root, ...root.querySelectorAll('*')];
  for (const element of elements) {
    for (const name of translatableAttributes) applyAttribute(element, name);
  }

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let node;
  while ((node = walker.nextNode())) applyText(node);
}

function setLanguage(nextLanguage) {
  language = nextLanguage === 'id' ? 'id' : 'en';
  document.documentElement.lang = language;
  try {
    localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
  } catch {
    // The language still applies for this session if storage is unavailable.
  }
  const selector = document.getElementById('languageSelect');
  if (selector && selector.value !== language) selector.value = language;
  applySubtree(document.body);
}

export function initializeI18n() {
  if (initialized) return;
  initialized = true;
  language = readLanguage();
  document.documentElement.lang = language;
  const selector = document.getElementById('languageSelect');
  if (selector) {
    selector.value = language;
    selector.addEventListener('change', () => setLanguage(selector.value));
  }

  if (!nativeConfirm) {
    nativeConfirm = window.confirm.bind(window);
    window.confirm = (message) => nativeConfirm(translateValue(String(message)));
  }

  applySubtree(document.body);
  observer = new MutationObserver((records) => {
    for (const record of records) {
      if (record.type === 'characterData') {
        applyText(record.target);
      } else if (record.type === 'attributes') {
        applyAttribute(record.target, record.attributeName);
      } else {
        for (const node of record.addedNodes) applySubtree(node);
      }
    }
  });
  observer.observe(document.body, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: translatableAttributes
  });
}
