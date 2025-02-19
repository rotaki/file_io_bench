use std::sync::atomic::{AtomicU32, Ordering};

pub type ContainerId = u16;

#[cfg(not(any(
    feature = "preadpwrite_sync",
    feature = "iouring_sync",
    feature = "inmemory_async_simulator",
    feature = "copy_async_simulator",
    feature = "iouring_async",
    feature = "async_write",
    feature = "new_async_write",
)))]
pub type FileManager = preadpwrite_sync::FileManager;

#[cfg(feature = "preadpwrite_sync")]
pub type FileManager = preadpwrite_sync::FileManager;
#[cfg(feature = "iouring_sync")]
pub type FileManager = iouring_sync::FileManager;
#[cfg(feature = "inmemory_async_simulator")]
pub type FileManager = inmemory_async_simulator::FileManager;
#[cfg(feature = "copy_async_simulator")]
pub type FileManager = copy_async_simulator::FileManager;
#[cfg(feature = "iouring_async")]
pub type FileManager = iouring_async::FileManager;
#[cfg(feature = "async_write")]
pub type FileManager = async_write::FileManager;
#[cfg(feature = "new_async_write")]
pub type FileManager = new_async_write::FileManager;

pub struct FileStats {
    pub buffered_read_count: AtomicU32,
    pub buffered_write_count: AtomicU32,
    pub direct_read_count: AtomicU32,
    pub direct_write_count: AtomicU32,
}

impl Clone for FileStats {
    fn clone(&self) -> Self {
        FileStats {
            buffered_read_count: AtomicU32::new(self.buffered_read_count.load(Ordering::Acquire)),
            buffered_write_count: AtomicU32::new(self.buffered_write_count.load(Ordering::Acquire)),
            direct_read_count: AtomicU32::new(self.direct_read_count.load(Ordering::Acquire)),
            direct_write_count: AtomicU32::new(self.direct_write_count.load(Ordering::Acquire)),
        }
    }
}

impl std::fmt::Display for FileStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Buffered read count: {}, Buffered write count: {}, Direct read count: {}, Direct write count: {}",
            self.buffered_read_count.load(Ordering::Acquire),
            self.buffered_write_count.load(Ordering::Acquire),
            self.direct_read_count.load(Ordering::Acquire),
            self.direct_write_count.load(Ordering::Acquire),
        )
    }
}

impl Default for FileStats {
    fn default() -> Self {
        Self::new()
    }
}

impl FileStats {
    pub fn new() -> Self {
        FileStats {
            buffered_read_count: AtomicU32::new(0),
            buffered_write_count: AtomicU32::new(0),
            direct_read_count: AtomicU32::new(0),
            direct_write_count: AtomicU32::new(0),
        }
    }

    pub fn read_count(&self) -> u32 {
        self.buffered_read_count.load(Ordering::Acquire)
            + self.direct_read_count.load(Ordering::Acquire)
    }

    pub fn inc_read_count(&self, direct: bool) {
        #[cfg(feature = "stat")]
        {
            if direct {
                self.direct_read_count.fetch_add(1, Ordering::AcqRel);
            } else {
                self.buffered_read_count.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    pub fn write_count(&self) -> u32 {
        self.buffered_write_count.load(Ordering::Acquire)
            + self.direct_write_count.load(Ordering::Acquire)
    }

    pub fn inc_write_count(&self, direct: bool) {
        #[cfg(feature = "stat")]
        {
            if direct {
                self.direct_write_count.fetch_add(1, Ordering::AcqRel);
            } else {
                self.buffered_write_count.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    pub fn reset(&self) {
        self.buffered_read_count.store(0, Ordering::Release);
        self.buffered_write_count.store(0, Ordering::Release);
        self.direct_read_count.store(0, Ordering::Release);
        self.direct_write_count.store(0, Ordering::Release);
    }
}

pub mod preadpwrite_sync {
    use super::{ContainerId, FileStats};
    #[allow(unused_imports)]
    use crate::log;
    use crate::log_trace;
    use crate::page::{Page, PageId, PAGE_SIZE};
    use libc::{c_void, fsync, pread, pwrite, O_DIRECT};
    use std::fs::{File, OpenOptions};
    use std::mem::MaybeUninit;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    pub struct FileManager {
        _path: PathBuf,
        _file: File, // When this file is dropped, the file descriptor (file_no) will be invalid.
        stats: FileStats,
        file_no: i32,
        direct: bool,
    }

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(O_DIRECT)
                .open(&path)?;
            let file_no = file.as_raw_fd();
            Ok(FileManager {
                _path: path,
                _file: file,
                stats: FileStats::new(),
                file_no,
                direct: true,
            })
        }

        // With kernel page cache
        pub fn with_kpc<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            let file_no = file.as_raw_fd();
            Ok(FileManager {
                _path: path,
                _file: file,
                stats: FileStats::new(),
                file_no,
                direct: false,
            })
        }

        pub fn num_pages(&self) -> usize {
            // Allocate uninitialized memory for libc::stat
            let mut stat = MaybeUninit::<libc::stat>::uninit();

            // Call fstat with a pointer to our uninitialized stat buffer
            let ret = unsafe { libc::fstat(self.file_no, stat.as_mut_ptr()) };

            // Check for errors (fstat returns -1 on failure)
            if ret == -1 {
                return 0;
            }

            // Now that fstat has successfully written to the buffer,
            // we can assume it is initialized.
            let stat = unsafe { stat.assume_init() };

            // Use the file size (st_size) from stat, then compute pages.
            (stat.st_size as usize) / PAGE_SIZE
        }

        pub fn get_stats(&self) -> FileStats {
            self.stats.clone()
        }

        pub fn prefetch_page(&self, _page_id: PageId) -> Result<(), std::io::Error> {
            Ok(())
        }

        pub fn read_page(&self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {
            self.stats.inc_read_count(self.direct);
            log_trace!("Reading page: {} from file: {:?}", page_id, self.path);
            unsafe {
                let ret = pread(
                    self.file_no,
                    page.get_raw_bytes_mut().as_mut_ptr() as *mut c_void,
                    PAGE_SIZE,
                    page_id as i64 * PAGE_SIZE as i64,
                );
                if ret != PAGE_SIZE as isize {
                    return Err(std::io::Error::last_os_error());
                }
            }
            debug_assert!(page.get_id() == page_id, "Page id mismatch");
            Ok(())
        }

        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            self.stats.inc_write_count(self.direct);
            log_trace!("Writing page: {} to file: {:?}", page_id, self.path);
            debug_assert!(page.get_id() == page_id, "Page id mismatch");
            unsafe {
                let ret = pwrite(
                    self.file_no,
                    page.get_raw_bytes().as_ptr() as *const c_void,
                    PAGE_SIZE,
                    page_id as i64 * PAGE_SIZE as i64,
                );
                if ret != PAGE_SIZE as isize {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        }

        // With psync_direct, we don't need to flush.
        pub fn flush(&self) -> Result<(), std::io::Error> {
            if self.direct {
                Ok(())
            } else {
                unsafe {
                    let ret = fsync(self.file_no);
                    if ret != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            }
        }
    }
}

pub mod iouring_sync {
    use super::{ContainerId, FileStats};
    #[allow(unused_imports)]
    use crate::log;
    use crate::page::{Page, PageId, PAGE_SIZE};
    use io_uring::{opcode, types, IoUring};
    use libc::O_DIRECT;
    use std::cell::RefCell;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    enum UserData {
        Read(PageId),
        Write(PageId),
        Flush,
    }

    impl UserData {
        fn as_u64(&self) -> u64 {
            // Higher 32 bits are the operation type.
            // Lower 32 bits are the page id.
            match self {
                UserData::Read(page_id) => {
                    let upper_32 = 0;
                    let lower_32 = *page_id as u64;
                    (upper_32 << 32) | lower_32
                }
                UserData::Write(page_id) => {
                    let upper_32 = 1;
                    let lower_32 = *page_id as u64;
                    (upper_32 << 32) | lower_32
                }
                UserData::Flush => {
                    let upper_32 = 2;
                    let lower_32 = 0;
                    (upper_32 << 32) | lower_32
                }
            }
        }

        fn new_from_u64(data: u64) -> Self {
            let upper_32 = (data >> 32) as u32;
            let lower_32 = data as u32;
            match upper_32 {
                0 => UserData::Read(lower_32),
                1 => UserData::Write(lower_32),
                2 => UserData::Flush,
                _ => panic!("Invalid user data"),
            }
        }

        fn new_read(page_id: PageId) -> Self {
            UserData::Read(page_id)
        }

        fn new_write(page_id: PageId) -> Self {
            UserData::Write(page_id)
        }

        fn new_flush() -> Self {
            UserData::Flush
        }
    }

    thread_local! {
        static PER_THREAD_RING: RefCell<IoUring> = RefCell::new(IoUring::new(128).unwrap());
    }

    pub struct PerThreadRing {}

    impl PerThreadRing {
        pub fn new() -> Self {
            PerThreadRing {}
        }

        pub fn read_page(
            &self,
            fileno: i32,
            page_id: PageId,
            page: &mut Page,
        ) -> Result<(), std::io::Error> {
            let buf = page.get_raw_bytes_mut();
            let entry = opcode::Read::new(types::Fd(fileno), buf.as_mut_ptr(), buf.len() as _)
                .offset(page_id as u64 * PAGE_SIZE as u64)
                .build()
                .user_data(UserData::new_read(page_id).as_u64());
            PER_THREAD_RING.with(|ring| {
                let mut ring = ring.borrow_mut();
                unsafe {
                    ring.submission().push(&entry).expect("queue is full");
                }
                let res = ring.submit_and_wait(1)?; // Submit and wait for completion of 1 operation.
                assert_eq!(res, 1); // This is true if SQPOLL is disabled.
                if let Some(entry) = ring.completion().next() {
                    let completed = entry.user_data();
                    let user_data = UserData::new_from_u64(completed);
                    if let UserData::Read(completed_page_id) = user_data {
                        assert_eq!(completed_page_id, page_id);
                    } else {
                        panic!("Invalid user data");
                    }
                } else {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
        }

        pub fn write_page(
            &self,
            fileno: i32,
            page_id: PageId,
            page: &Page,
        ) -> Result<(), std::io::Error> {
            let buf = page.get_raw_bytes();
            let entry = opcode::Write::new(types::Fd(fileno), buf.as_ptr(), buf.len() as _)
                .offset(page_id as u64 * PAGE_SIZE as u64)
                .build()
                .user_data(UserData::new_write(page_id).as_u64());
            PER_THREAD_RING.with(|ring| {
                let mut ring = ring.borrow_mut();
                unsafe {
                    ring.submission().push(&entry).expect("queue is full");
                }
                let res = ring.submit_and_wait(1)?; // Submit and wait for completion of 1 operation.
                assert_eq!(res, 1); // This is true if SQPOLL is disabled.
                if let Some(entry) = ring.completion().next() {
                    let completed = entry.user_data();
                    let user_data = UserData::new_from_u64(completed);
                    if let UserData::Write(completed_page_id) = user_data {
                        assert_eq!(completed_page_id, page_id);
                    } else {
                        panic!("Invalid user data");
                    }
                } else {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
        }

        pub fn flush(&self, fileno: i32) -> Result<(), std::io::Error> {
            let entry = opcode::Fsync::new(types::Fd(fileno))
                .build()
                .user_data(UserData::new_flush().as_u64());
            PER_THREAD_RING.with(|ring| {
                let mut ring = ring.borrow_mut();
                unsafe {
                    ring.submission().push(&entry).expect("queue is full");
                }
                let res = ring.submit_and_wait(1)?; // Submit and wait for completion of 1 operation.
                assert_eq!(res, 1); // This is true if SQPOLL is disabled.
                if let Some(entry) = ring.completion().next() {
                    let completed = entry.user_data();
                    let user_data = UserData::new_from_u64(completed);
                    if let UserData::Flush = user_data {
                        // Do nothing
                    } else {
                        panic!("Invalid user data");
                    }
                } else {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
        }
    }

    pub struct FileManager {
        _path: PathBuf,
        _file: File,
        stats: FileStats,
        fileno: i32,
        direct: bool,
    }

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(O_DIRECT)
                .open(&path)?;
            let fileno = file.as_raw_fd();
            Ok(FileManager {
                _path: path,
                _file: file,
                stats: FileStats::new(),
                fileno,
                direct: true,
            })
        }

        // With kernel page cache. O_DIRECT is not set.
        pub fn with_kpc<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            let fileno = file.as_raw_fd();
            Ok(FileManager {
                _path: path,
                _file: file,
                stats: FileStats::new(),
                fileno,
                direct: false,
            })
        }

        pub fn get_stats(&self) -> FileStats {
            self.stats.clone()
        }

        pub fn prefetch_page(&self, page_id: PageId) -> Result<(), std::io::Error> {
            Ok(())
        }

        pub fn read_page(&self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {
            self.stats.inc_read_count(self.direct);
            PerThreadRing::new().read_page(self.fileno, page_id, page)
        }

        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            self.stats.inc_write_count(self.direct);
            PerThreadRing::new().write_page(self.fileno, page_id, page)
        }

        pub fn flush(&self) -> Result<(), std::io::Error> {
            if !self.direct {
                Ok(())
            } else {
                PerThreadRing::new().flush(self.fileno)
            }
        }
    }
}

pub mod inmemory_async_simulator {
    use super::ContainerId;
    use crate::page::{Page, PageId};
    use std::sync::Mutex;
    const NUM_PAGE_BUFFER: usize = 128;

    pub struct FileManager {
        temp_buffers: Vec<Mutex<Page>>,
    }

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            _db_dir: P,
            _c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            Ok(FileManager {
                temp_buffers: (0..NUM_PAGE_BUFFER)
                    .map(|_| Mutex::new(Page::new_empty()))
                    .collect(),
            })
        }

        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            let idx = page_id as usize % NUM_PAGE_BUFFER as usize;
            let mut temp_buffer = self.temp_buffers[idx].lock().unwrap();
            temp_buffer.copy(page);
            Ok(())
        }
    }
}

pub mod copy_async_simulator {
    use std::{
        fs::{File, OpenOptions},
        os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
        sync::Mutex,
    };

    use io_uring::IoUring;
    use libc::O_DIRECT;

    use crate::page::{Page, PageId};

    use super::ContainerId;

    const NUM_PAGE_BUFFER: usize = 128;

    pub struct FileManager {
        _file: File,
        fileno: i32,
        temp_buffers: Vec<Mutex<(IoUring, Page)>>,
    }

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(O_DIRECT)
                .open(&path)?;
            let fileno = file.as_raw_fd();
            Ok(FileManager {
                _file: file,
                fileno,
                temp_buffers: (0..NUM_PAGE_BUFFER)
                    .map(|_| Mutex::new((IoUring::new(128).unwrap(), Page::new_empty())))
                    .collect(),
            })
        }

        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            let idx = page_id as usize % NUM_PAGE_BUFFER as usize;
            let mut lock = self.temp_buffers[idx].lock().unwrap();
            let (ring, temp_buffer) = &mut *lock;
            temp_buffer.copy(page);
            let buf = temp_buffer.get_raw_bytes();
            let entry = io_uring::opcode::Write::new(
                io_uring::types::Fd(self.fileno),
                buf.as_ptr() as _,
                buf.len() as _,
            )
            .offset(page_id as u64 * crate::page::PAGE_SIZE as u64)
            .build()
            .user_data(page_id as u64);

            unsafe {
                ring.submission().push(&entry).expect("queue is full");
            }
            let _res = ring.submit_and_wait(1)?; // Submit and wait for completion of 1 operation.
            assert_eq!(_res, 1); // This is true if SQPOLL is disabled.

            // Poll for completion.
            loop {
                if let Some(entry) = ring.completion().next() {
                    let _completed = entry.user_data();
                    assert_eq!(page_id, _completed as PageId);
                    break;
                } else {
                    std::hint::spin_loop();
                }
            }

            Ok(())
        }
    }
}

pub mod iouring_async {
    use super::{ContainerId, FileStats};
    #[allow(unused_imports)]
    use crate::log;
    use crate::page::{Page, PageId, PAGE_SIZE};
    use io_uring::{opcode, types, IoUring};
    use libc::{iovec, O_DIRECT};
    use std::cell::UnsafeCell;
    use std::fs::{File, OpenOptions};
    use std::hash::{Hash, Hasher};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::OnceLock;

    enum UserData {
        Read(PageId),
        Write(PageId),
        Flush,
    }

    impl UserData {
        fn as_u64(&self) -> u64 {
            // Higher 32 bits are the operation type.
            // Lower 32 bits are the page id.
            match self {
                UserData::Read(page_id) => {
                    let upper_32 = 0;
                    let lower_32 = *page_id as u64;
                    (upper_32 << 32) | lower_32
                }
                UserData::Write(page_id) => {
                    let upper_32 = 1;
                    let lower_32 = *page_id as u64;
                    (upper_32 << 32) | lower_32
                }
                UserData::Flush => {
                    let upper_32 = 2;
                    let lower_32 = 0;
                    (upper_32 << 32) | lower_32
                }
            }
        }

        fn new_from_u64(data: u64) -> Self {
            let upper_32 = (data >> 32) as u32;
            let lower_32 = data as u32;
            match upper_32 {
                0 => UserData::Read(lower_32),
                1 => UserData::Write(lower_32),
                2 => UserData::Flush,
                _ => panic!("Invalid user data"),
            }
        }

        fn new_read(page_id: PageId) -> Self {
            UserData::Read(page_id)
        }

        fn new_write(page_id: PageId) -> Self {
            UserData::Write(page_id)
        }

        fn new_flush() -> Self {
            UserData::Flush
        }
    }

    pub struct PerPageHashRing {
        lock: Mutex<()>,
        ring: UnsafeCell<IoUring>,
        has_pending_write: UnsafeCell<bool>,
        temp_buffer: UnsafeCell<Page>,
        _io_vec: UnsafeCell<[iovec; 1]>,
    }

    unsafe impl Send for PerPageHashRing {}
    unsafe impl Sync for PerPageHashRing {}

    impl PerPageHashRing {
        pub fn new() -> Self {
            let ring = IoUring::builder().build(128).unwrap();
            let temp_buffer = UnsafeCell::new(Page::new_empty());
            let io_vec = UnsafeCell::new(unsafe {
                let io_vec: [iovec; 1] = [iovec {
                    iov_base: (*temp_buffer.get()).get_raw_bytes_mut().as_mut_ptr() as _,
                    iov_len: PAGE_SIZE as _,
                }];
                io_vec
            });
            // Register the file and the page buffer with the io_uring.
            let submitter = &ring.submitter();
            unsafe {
                submitter.register_buffers(&*io_vec.get()).unwrap();
            }
            PerPageHashRing {
                lock: Mutex::new(()),
                ring: UnsafeCell::new(ring),
                has_pending_write: UnsafeCell::new(false),
                temp_buffer,
                _io_vec: io_vec,
            }
        }

        pub fn read(
            &self,
            fileno: i32,
            page_id: PageId,
            page: &mut Page,
        ) -> Result<(), std::io::Error> {
            let buf = page.get_raw_bytes_mut();
            let entry = opcode::Read::new(types::Fd(fileno), buf.as_mut_ptr(), buf.len() as _)
                .offset(page_id as u64 * PAGE_SIZE as u64)
                .build()
                .user_data(UserData::new_read(page_id).as_u64());

            let lock = self.lock.lock().unwrap();
            let ring = unsafe { &mut *self.ring.get() };
            let has_pending_writes = unsafe { &mut *self.has_pending_write.get() };
            let temp_buffer = unsafe { &mut *self.temp_buffer.get() };

            // If the page_buffer contains the same page, we don't need to read it from disk.
            if temp_buffer.get_id() == page_id {
                // Copy to the destination page.
                page.copy(temp_buffer);
                return Ok(()); // Return early.
            }

            unsafe {
                ring.submission().push(&entry).expect("queue is full");
            }
            // Submit and wait for completion of at least 1 operation.
            let ret = ring.submit_and_wait(1)?;
            assert_eq!(ret, 1); // This is true if SQPOLL is disabled.

            // Keep polling until the read is completed.
            loop {
                if let Some(entry) = ring.completion().next() {
                    let completed = entry.user_data();
                    let user_data = UserData::new_from_u64(completed);
                    match user_data {
                        UserData::Read(completion_id) => {
                            assert_eq!(completion_id, page_id);
                            assert_eq!(completion_id, page.get_id());
                            // Copying is done after the read is completed.
                            break;
                        }
                        UserData::Write(_) => {
                            *has_pending_writes = false;
                        }
                        UserData::Flush => {
                            // Do nothing.
                        }
                    }
                } else {
                    std::hint::spin_loop();
                }
            }

            drop(lock);

            Ok(())
        }

        pub fn write(
            &self,
            fileno: i32,
            page_id: PageId,
            page: &Page,
        ) -> Result<(), std::io::Error> {
            // 1. Create a write operation.
            let buf = unsafe { &*self.temp_buffer.get() }.get_raw_bytes();
            let entry = opcode::Write::new(types::Fd(fileno), buf.as_ptr(), buf.len() as _)
                .offset(page_id as u64 * PAGE_SIZE as u64)
                .build()
                .user_data(UserData::new_write(page_id).as_u64());

            let lock = self.lock.lock().unwrap();
            let ring = unsafe { &mut *self.ring.get() };
            let has_pending_write = unsafe { &mut *self.has_pending_write.get() };
            let temp_buffer = unsafe { &mut *self.temp_buffer.get() };

            // If there are pending writes, poll the ring first.
            if *has_pending_write {
                // println!("waiting for pending write");
                loop {
                    if let Some(entry) = ring.completion().next() {
                        let completed = entry.user_data();
                        let user_data = UserData::new_from_u64(completed);
                        match user_data {
                            UserData::Read(_) => {
                                // Do nothing.
                                panic!("Read should be synchronous");
                            }
                            UserData::Write(completion_id) => {
                                assert_eq!(completion_id, temp_buffer.get_id());
                                *has_pending_write = false;
                                break;
                            }
                            UserData::Flush => {
                                // Do nothing.
                            }
                        }
                    } else {
                        std::hint::spin_loop();
                    }
                }
            }

            // Now we can write the new page to the temp buffer.
            // 1. Copy the page to the temp buffer.
            temp_buffer.copy(page);
            // 2. Push the write operation to the ring.
            unsafe {
                ring.submission().push(&entry).expect("queue is full");
            }
            // 3. Submit.
            let _res = ring.submit()?; // Submit and wait for completion of 1 operation.
            assert_eq!(_res, 1); // This is true if SQPOLL is disabled.
            *has_pending_write = true;
            drop(lock);

            Ok(())
        }

        pub fn flush(&self, fileno: i32) -> Result<(), std::io::Error> {
            let entry = opcode::Fsync::new(types::Fd(fileno))
                .build()
                .user_data(UserData::new_flush().as_u64());

            let lock = self.lock.lock().unwrap();
            let ring = unsafe { &mut *self.ring.get() };
            let has_pending_write = unsafe { &mut *self.has_pending_write.get() };
            let temp_buffer = unsafe { &mut *self.temp_buffer.get() };

            // If there are pending writes, poll the ring first.
            if *has_pending_write {
                loop {
                    if let Some(entry) = ring.completion().next() {
                        let completed = entry.user_data();
                        let user_data = UserData::new_from_u64(completed);
                        match user_data {
                            UserData::Read(_) => {
                                // Do nothing.
                                panic!("Read should be synchronous");
                            }
                            UserData::Write(completion_id) => {
                                assert_eq!(completion_id, temp_buffer.get_id());
                                *has_pending_write = false;
                                break;
                            }
                            UserData::Flush => {
                                // Do nothing.
                            }
                        }
                    } else {
                        std::hint::spin_loop();
                    }
                }
            }

            // 1. Push the flush operation to the ring.
            unsafe {
                ring.submission().push(&entry).expect("queue is full");
            }
            // 2. Submit.
            let _res = ring.submit()?; // Submit
            assert_eq!(_res, 1); // This is true if SQPOLL is disabled.
            drop(lock);

            Ok(())
        }
    }

    // Static per hash ring
    static RINGS: OnceLock<Vec<PerPageHashRing>> = OnceLock::new();

    const NUM_RINGS: usize = 10;

    pub struct GlobalRing {}

    impl GlobalRing {
        pub fn new() -> Self {
            Self {}
        }

        pub fn get(&self, fileno: i32, page_id: PageId) -> &PerPageHashRing {
            let rings = RINGS.get_or_init(|| {
                (0..NUM_RINGS)
                    .map(|_| PerPageHashRing::new())
                    .collect::<Vec<_>>()
            });
            let index = self.hash(fileno, page_id);
            &rings[index]
        }

        fn hash(&self, fileno: i32, page_id: PageId) -> usize {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            (fileno, page_id).hash(&mut hasher);
            hasher.finish() as usize % NUM_RINGS
        }

        pub fn read_page(
            &self,
            fileno: i32,
            page_id: PageId,
            page: &mut Page,
        ) -> Result<(), std::io::Error> {
            // Compute a hash based on fileno and page id
            let ring = self.get(fileno, page_id);
            ring.read(fileno, page_id, page)
        }

        pub fn write_page(
            &self,
            fileno: i32,
            page_id: PageId,
            page: &Page,
        ) -> Result<(), std::io::Error> {
            let ring = self.get(fileno, page_id);
            ring.write(fileno, page_id, page)
        }

        pub fn flush(&self, fileno: i32) -> Result<(), std::io::Error> {
            let ring_vec = RINGS.get().unwrap();
            for ring in ring_vec {
                ring.flush(fileno)?;
            }

            Ok(())
        }
    }

    pub struct FileManager {
        _path: PathBuf,
        _file: File,
        stats: FileStats,
        fileno: i32,
        direct: bool,
    }

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(O_DIRECT)
                .open(&path)?;
            let fileno = file.as_raw_fd();
            Ok(FileManager {
                _path: path,
                _file: file,
                stats: FileStats::new(),
                fileno,
                direct: true,
            })
        }

        // With kernel page cache. O_DIRECT is not set.
        pub fn with_kpc<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            let fileno = file.as_raw_fd();
            Ok(FileManager {
                _path: path,
                _file: file,
                stats: FileStats::new(),
                fileno,
                direct: false,
            })
        }

        pub fn get_stats(&self) -> FileStats {
            self.stats.clone()
        }

        pub fn prefetch_page(&self, page_id: PageId) -> Result<(), std::io::Error> {
            Ok(())
        }

        pub fn read_page(&self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {
            self.stats.inc_read_count(self.direct);
            GlobalRing::new().read_page(self.fileno, page_id, page)
        }

        // Writes are asynchronous. It is not guaranteed that the write is completed when this function returns.
        // We guarantee that the write is completed before a new I/O operation is started on the same page.
        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            self.stats.inc_write_count(self.direct);
            GlobalRing::new().write_page(self.fileno, page_id, page)
        }

        pub fn flush(&self) -> Result<(), std::io::Error> {
            if !self.direct {
                Ok(())
            } else {
                GlobalRing::new().flush(self.fileno)
            }
        }
    }
}
/*
pub mod iouring_direct {
    use super::ContainerId;
    #[allow(unused_imports)]
    use crate::log;
    use crate::page::{Page, PageId, PAGE_SIZE};
    use crate::{log_debug, log_trace};
    use std::cell::UnsafeCell;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use std::sync::Mutex;

    use io_uring::{opcode, types, IoUring};
    use libc::{iovec, O_DIRECT};
    use std::hash::{Hash, Hasher};
    use std::os::unix::io::AsRawFd;

    const PAGE_BUFFER_SIZE: usize = 128;

    pub struct FileManager {
        #[allow(dead_code)]
        path: PathBuf,
        file_inner: Mutex<FileManagerInner>,
    }

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(O_DIRECT)
                .open(&path)?;
            let file_inner = FileManagerInner::new(file)?;
            Ok(FileManager {
                path,
                file_inner: Mutex::new(file_inner),
            })

            let ring = IoUring::builder()
                .setup_sqpoll(1)
                .build(PAGE_BUFFER_SIZE as _)?;
            let mut page_buffer: Vec<Page> = (0..PAGE_BUFFER_SIZE)
                .map(|_| Page::new(PageId::MAX))
                .collect();
            let io_vec = page_buffer
                .iter_mut()
                .map(|page| iovec {
                    iov_base: page.get_raw_bytes_mut().as_mut_ptr() as _,
                    iov_len: PAGE_SIZE as _,
                })
                .collect::<Vec<_>>();
            // Register the file and the page buffer with the io_uring.
            let submitter = &ring.submitter();
            submitter.register_files(&[file.as_raw_fd()])?;
            unsafe {
                submitter.register_buffers(&io_vec)?;
            }
            Ok(FileManagerInner {
                _file: file,
                ring,
                page_buffer_status: (0..PAGE_BUFFER_SIZE).map(|_| true).collect(),
                page_buffer,
                _io_vec: UnsafeCell::new(io_vec),
            })
        }

        #[allow(dead_code)]
        pub fn get_stats(&self) -> String {
            #[cfg(feature = "stat")]
            {
                let stats = GLOBAL_FILE_STAT.lock().unwrap();
                LOCAL_STAT.with(|local_stat| {
                    stats.merge(&local_stat.stat);
                    local_stat.stat.clear();
                });
                return stats.to_string();
            }
            #[cfg(not(feature = "stat"))]
            {
                "Stat is disabled".to_string()
            }
        }

        pub fn prefetch_page(&self, page_id: PageId) -> Result<(), std::io::Error> {
            Ok(())
        }

        pub fn read_page(&self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {
            log_trace!("Reading page: {} from file: {:?}", page_id, self.path);
            let mut file_inner = self.file_inner.lock().unwrap();
            file_inner.read_page(page_id, page)
        }

        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            log_trace!("Writing page: {} to file: {:?}", page_id, self.path);
            let mut file_inner = self.file_inner.lock().unwrap();
            file_inner.write_page(page_id, page)
        }

        pub fn flush(&self) -> Result<(), std::io::Error> {
            log_trace!("Flushing file: {:?}", self.path);
            let mut file_inner = self.file_inner.lock().unwrap();
            file_inner.flush()
        }
    }

    #[cfg(feature = "stat")]
    mod stat {
        use super::*;
        use lazy_static::lazy_static;
        pub struct FileStat {
            read: UnsafeCell<[usize; 11]>, // Number of reads completed. The index is the wait count.
            write: UnsafeCell<[usize; 11]>, // Number of writes completed. The index is the wait count.
        }

        impl FileStat {
            pub fn new() -> Self {
                FileStat {
                    read: UnsafeCell::new([0; 11]),
                    write: UnsafeCell::new([0; 11]),
                }
            }

            pub fn to_string(&self) -> String {
                let read = unsafe { &*self.read.get() };
                let write = unsafe { &*self.write.get() };
                let mut result = String::new();
                result.push_str("File page async read stats: \n");
                let mut sep = "";
                let total_count = read.iter().sum::<usize>();
                let mut cumulative_count = 0;
                for i in 0..11 {
                    result.push_str(sep);
                    cumulative_count += read[i];
                    if i == 10 {
                        result.push_str(&format!(
                            "{:2}+: {:6} (p: {:6.2}%, c: {:6})",
                            i,
                            read[i],
                            read[i] as f64 / total_count as f64 * 100.0,
                            cumulative_count
                        ));
                    } else {
                        result.push_str(&format!(
                            "{:3}: {:6} (p: {:6.2}%, c: {:6})",
                            i,
                            read[i],
                            read[i] as f64 / total_count as f64 * 100.0,
                            cumulative_count
                        ));
                    }
                    sep = "\n";
                }
                result.push_str("\n\n");
                result.push_str("File page async write stats: \n");
                sep = "";
                let total_count = write.iter().sum::<usize>();
                cumulative_count = 0;
                for i in 0..11 {
                    result.push_str(sep);
                    cumulative_count += write[i];
                    if i == 10 {
                        result.push_str(&format!(
                            "{:2}+: {:6} (p: {:6.2}%, c: {:6})",
                            i,
                            write[i],
                            write[i] as f64 / total_count as f64 * 100.0,
                            cumulative_count
                        ));
                    } else {
                        result.push_str(&format!(
                            "{:3}: {:6} (p: {:6.2}%, c: {:6})",
                            i,
                            write[i],
                            write[i] as f64 / total_count as f64 * 100.0,
                            cumulative_count
                        ));
                    }
                    sep = "\n";
                }
                result
            }

            pub fn merge(&self, other: &FileStat) {
                let read = unsafe { &mut *self.read.get() };
                let other_read = unsafe { &*other.read.get() };
                let write = unsafe { &mut *self.write.get() };
                let other_write = unsafe { &*other.write.get() };
                for i in 0..11 {
                    read[i] += other_read[i];
                    write[i] += other_write[i];
                }
            }

            pub fn clear(&self) {
                let read = unsafe { &mut *self.read.get() };
                let write = unsafe { &mut *self.write.get() };
                for i in 0..11 {
                    read[i] = 0;
                    write[i] = 0;
                }
            }
        }

        pub struct LocalStat {
            pub stat: FileStat,
        }

        impl Drop for LocalStat {
            fn drop(&mut self) {
                let global_stat = GLOBAL_FILE_STAT.lock().unwrap();
                global_stat.merge(&self.stat);
            }
        }

        lazy_static! {
            pub static ref GLOBAL_FILE_STAT: Mutex<FileStat> = Mutex::new(FileStat::new());
        }

        thread_local! {
            pub static LOCAL_STAT: LocalStat = LocalStat {
                stat: FileStat::new()
            };
        }

        pub fn inc_local_read_stat(wait_count: usize) {
            LOCAL_STAT.with(|local_stat| {
                let stat = &local_stat.stat;
                let read = unsafe { &mut *stat.read.get() };
                if wait_count >= 10 {
                    read[10] += 1;
                } else {
                    read[wait_count] += 1;
                }
            });
        }

        pub fn inc_local_write_stat(wait_count: usize) {
            LOCAL_STAT.with(|local_stat| {
                let stat = &local_stat.stat;
                let write = unsafe { &mut *stat.write.get() };
                if wait_count >= 10 {
                    write[10] += 1;
                } else {
                    write[wait_count] += 1;
                }
            });
        }
    }

    #[cfg(feature = "stat")]
    use stat::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum IOOp {
        Read,
        Write,
        Flush,
    }

    impl IOOp {
        fn as_u32(&self) -> u32 {
            match self {
                IOOp::Read => 0,
                IOOp::Write => 1,
                IOOp::Flush => 2,
            }
        }
    }

    impl From<u32> for IOOp {
        fn from(op: u32) -> Self {
            match op {
                0 => IOOp::Read,
                1 => IOOp::Write,
                2 => IOOp::Flush,
                _ => panic!("Invalid IOOp"),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct IOOpTag {
        op: IOOp,
        page_id: PageId,
    }

    impl IOOpTag {
        fn get_op(&self) -> IOOp {
            self.op
        }

        fn get_id(&self) -> PageId {
            self.page_id
        }

        fn new_read(page_id: PageId) -> Self {
            IOOpTag {
                op: IOOp::Read,
                page_id,
            }
        }

        fn new_write(page_id: PageId) -> Self {
            IOOpTag {
                op: IOOp::Write,
                page_id,
            }
        }

        fn new_flush() -> Self {
            IOOpTag {
                op: IOOp::Flush,
                page_id: PageId::MAX,
            }
        }

        fn as_u64(&self) -> u64 {
            let upper_32 = self.op.as_u32() as u64;
            let lower_32 = self.page_id as u64;
            (upper_32 << 32) | lower_32
        }
    }

    impl From<u64> for IOOpTag {
        fn from(tag: u64) -> Self {
            let upper_32 = (tag >> 32) as u32;
            let lower_32 = tag as u32;
            IOOpTag {
                op: IOOp::from(upper_32),
                page_id: lower_32,
            }
        }
    }

    unsafe impl Send for FileManagerInner {} // Send is needed for io_vec

    struct FileManagerInner {
        _file: File,
        ring: IoUring,
        page_buffer_status: Vec<bool>, // Written = true, Not written = false
        page_buffer: Vec<Page>,
        _io_vec: UnsafeCell<Vec<iovec>>, // We have to keep this in-memory for the lifetime of the io_uring.
    }

    impl FileManagerInner {
        fn new(file: File) -> Result<Self, std::io::Error> {
            let ring = IoUring::builder()
                .setup_sqpoll(1)
                .build(PAGE_BUFFER_SIZE as _)?;
            let mut page_buffer: Vec<Page> = (0..PAGE_BUFFER_SIZE)
                .map(|_| Page::new(PageId::MAX))
                .collect();
            let io_vec = page_buffer
                .iter_mut()
                .map(|page| iovec {
                    iov_base: page.get_raw_bytes_mut().as_mut_ptr() as _,
                    iov_len: PAGE_SIZE as _,
                })
                .collect::<Vec<_>>();
            // Register the file and the page buffer with the io_uring.
            let submitter = &ring.submitter();
            submitter.register_files(&[file.as_raw_fd()])?;
            unsafe {
                submitter.register_buffers(&io_vec)?;
            }
            Ok(FileManagerInner {
                _file: file,
                ring,
                page_buffer_status: (0..PAGE_BUFFER_SIZE).map(|_| true).collect(),
                page_buffer,
                _io_vec: UnsafeCell::new(io_vec),
            })
        }

        fn compute_hash(page_id: PageId) -> usize {
            // For safety, we take the Rust std::hash function
            // instead of a simple page_id as usize % PAGE_BUFFER_SIZE
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            page_id.hash(&mut hasher);
            hasher.finish() as usize % PAGE_BUFFER_SIZE
        }

        fn read_page(&mut self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {
            // Check the entry in the page_buffer
            let hash = FileManagerInner::compute_hash(page_id);
            let mut _count = 0;
            if page_id == self.page_buffer[hash].get_id() {
                page.copy(&self.page_buffer[hash]);
            } else {
                // If the page is not in the buffer, read from the file.
                let buf = page.get_raw_bytes_mut();
                let entry = opcode::Read::new(types::Fixed(0), buf.as_mut_ptr(), buf.len() as _)
                    .offset(page_id as u64 * PAGE_SIZE as u64)
                    .build()
                    .user_data(IOOpTag::new_read(page_id).as_u64());
                unsafe {
                    self.ring.submission().push(&entry).expect("queue is full");
                }
                let _res = self.ring.submit()?;
                // assert_eq!(res, 1); // This is true if SQPOLL is disabled.

                loop {
                    if let Some(entry) = self.ring.completion().next() {
                        let tag = IOOpTag::from(entry.user_data());
                        _count += 1;
                        match tag.get_op() {
                            IOOp::Read => {
                                // Reads are run in sequence, so this should be the page we are interested in.
                                assert_eq!(tag.get_id(), page_id);
                                break;
                            }
                            IOOp::Write => {
                                let this_page_id = tag.get_id();
                                let this_hash = FileManagerInner::compute_hash(this_page_id);
                                self.page_buffer_status[this_hash] = true; // Mark the page as written.
                            }
                            IOOp::Flush => {
                                // Do nothing
                            }
                        }
                    } else {
                        std::hint::spin_loop();
                    }
                }
            }

            log_debug!(
                "Read completed for page: {} with wait count: {}",
                page_id,
                _count
            );
            #[cfg(feature = "stat")]
            inc_local_read_stat(_count);
            Ok(())
        }

        fn write_page(&mut self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            // Check the entry in the page_buffer
            let hash = FileManagerInner::compute_hash(page_id);
            let mut _count = 0;
            loop {
                // Check the status of the page buffer.
                if self.page_buffer_status[hash] {
                    // If the page is written, overwrite the page and issue an async write.
                    self.page_buffer_status[hash] = false; // Mark the page as not written.
                    self.page_buffer[hash].copy(page);
                    let buf = self.page_buffer[hash].get_raw_bytes();
                    let entry = opcode::WriteFixed::new(
                        types::Fixed(0),
                        buf.as_ptr(),
                        buf.len() as _,
                        hash as _,
                    )
                    .offset(page_id as u64 * PAGE_SIZE as u64)
                    .build()
                    .user_data(IOOpTag::new_write(page_id).as_u64());
                    unsafe {
                        self.ring.submission().push(&entry).expect("queue is full");
                    }
                    let _res = self.ring.submit()?;
                    // assert_eq!(res, 1); // This is true if SQPOLL is disabled.
                    log_debug!(
                        "Write completed for page: {} with wait count: {}",
                        page_id,
                        _count
                    );
                    #[cfg(feature = "stat")]
                    inc_local_write_stat(_count);
                    return Ok(()); // This is the only return point.
                } else {
                    // If the page is not written, wait for the write to complete.
                    loop {
                        if let Some(entry) = self.ring.completion().next() {
                            _count += 1;
                            let tag = IOOpTag::from(entry.user_data());
                            match tag.get_op() {
                                IOOp::Write => {
                                    let this_page_id = tag.get_id();
                                    let this_hash = FileManagerInner::compute_hash(this_page_id);
                                    self.page_buffer_status[this_hash] = true; // Mark the page as written.
                                    if this_hash == hash {
                                        break; // Write completed for the buffer we are interested in.
                                    }
                                }
                                IOOp::Flush => {
                                    // Do nothing
                                }
                                IOOp::Read => {
                                    // Read should run synchronously, so this should not happen.
                                    panic!("Read should not be completed while waiting for write")
                                }
                            }
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                }
            }
        }

        fn flush(&mut self) -> Result<(), std::io::Error> {
            // Find the first entry in the page_buffer that is not written. Wait for it to be written.
            for i in 0..PAGE_BUFFER_SIZE {
                if !self.page_buffer_status[i] {
                    let mut _count = 0;
                    loop {
                        if let Some(entry) = self.ring.completion().next() {
                            _count += 1;
                            let tag = IOOpTag::from(entry.user_data());
                            match tag.get_op() {
                                IOOp::Write => {
                                    let this_page_id = tag.get_id();
                                    let this_hash = FileManagerInner::compute_hash(this_page_id);
                                    self.page_buffer_status[this_hash] = true; // Mark the page as written.
                                    if this_hash == i {
                                        break; // Write completed for the buffer we are interested in.
                                    }
                                }
                                IOOp::Flush => {
                                    // Do nothing
                                }
                                IOOp::Read => {
                                    // Read should run synchronously, so this should not happen.
                                    panic!("Read should not be completed while waiting for write")
                                }
                            }
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                }
            }
            assert!(self.page_buffer_status.iter().all(|&x| x));
            // Now issue a flush operation.
            let entry = opcode::Fsync::new(types::Fixed(0))
                .build()
                .user_data(IOOpTag::new_flush().as_u64());
            unsafe {
                self.ring.submission().push(&entry).expect("queue is full");
            }
            let res = self.ring.submit_and_wait(1)?;
            assert_eq!(res, 1);

            // Check the completion queue for the flush operation.
            let entry = self.ring.completion().next().unwrap();
            let tag = IOOpTag::from(entry.user_data());
            assert_eq!(tag.get_op(), IOOp::Flush);

            Ok(())
        }
    }
}


/*
pub mod iouring_direct {
    use super::{ContainerId, FileStats};
    #[allow(unused_imports)]
    use crate::log;
    use crate::page::{Page, PageId, PAGE_SIZE};
    use crate::{log_debug, log_trace};
    use std::cell::UnsafeCell;
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;

    use std::sync::Mutex;

    use io_uring::{opcode, types, IoUring};
    use libc::{iovec, O_DIRECT};
    use std::hash::{Hash, Hasher};
    use std::os::unix::io::AsRawFd;

    pub struct IOUrings {
        pub rings: Vec<IoUring>,
    }

    impl IOUrings {
        pub fn register_files(&self, fileno: i32) -> Result<(), std::io::Error> {
            // Must ensure that file during the lifetime of the IOUring.
            // Register the file to all the rings.
        }
    }

    pub struct FileManager {
        _path: PathBuf,
        _file: File,
        stats: FileStats,
        file_no: i32,
        temp_write_buffer: Vec<Page>,
    }

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            Self::new_with_buffer_size(db_dir, c_id, 128)
        }

        pub fn new_with_buffer_size<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
            buffer_size: usize,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .custom_flags(O_DIRECT)
                .open(&path)?;
            let file_no = file.as_raw_fd();
            let temp_write_buffer = (0..buffer_size).map(|_| Page::new_empty()).collect();
            Ok(FileManager {
                _path: path,
                _file: file,
                stats: FileStats::new(),
                file_no,
                temp_write_buffer,
            })
        }

        pub fn stats(&self) -> FileStats {
            self.stats.clone()
        }

        pub fn read_page(&self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {

        }

        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {

        }
    }
}
    */

pub mod async_write {
    use super::ContainerId;
    #[allow(unused_imports)]
    use crate::log;
    use crate::page::{Page, PageId, PAGE_SIZE};
    use crate::{log_debug, log_trace};
    use std::cell::UnsafeCell;
    use std::fs::{File, OpenOptions};
    use std::path::PathBuf;

    use std::sync::Mutex;

    use io_uring::{opcode, types, IoUring};
    use libc::iovec;
    use std::hash::{Hash, Hasher};
    use std::os::unix::io::AsRawFd;

    const PAGE_BUFFER_SIZE: usize = 128;

    pub struct FileManager {
        #[allow(dead_code)]
        path: PathBuf,
        file_inner: Mutex<FileManagerInner>,
    }

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            let file_inner = FileManagerInner::new(file)?;
            Ok(FileManager {
                path,
                file_inner: Mutex::new(file_inner),
            })
        }

        #[allow(dead_code)]
        pub fn get_stats(&self) -> String {
            #[cfg(feature = "stat")]
            {
                let stats = GLOBAL_FILE_STAT.lock().unwrap();
                LOCAL_STAT.with(|local_stat| {
                    stats.merge(&local_stat.stat);
                    local_stat.stat.clear();
                });
                return stats.to_string();
            }
            #[cfg(not(feature = "stat"))]
            {
                "Stat is disabled".to_string()
            }
        }

        pub fn prefetch_page(&self, page_id: PageId) -> Result<(), std::io::Error> {
            Ok(())
        }

        pub fn read_page(&self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {
            log_trace!("Reading page: {} from file: {:?}", page_id, self.path);
            let mut file_inner = self.file_inner.lock().unwrap();
            file_inner.read_page(page_id, page)
        }

        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            log_trace!("Writing page: {} to file: {:?}", page_id, self.path);
            let mut file_inner = self.file_inner.lock().unwrap();
            file_inner.write_page(page_id, page)
        }

        pub fn flush(&self) -> Result<(), std::io::Error> {
            log_trace!("Flushing file: {:?}", self.path);
            let mut file_inner = self.file_inner.lock().unwrap();
            file_inner.flush()
        }
    }

    #[cfg(feature = "stat")]
    mod stat {
        use super::*;
        use lazy_static::lazy_static;
        pub struct FileStat {
            read: UnsafeCell<[usize; 11]>, // Number of reads completed. The index is the wait count.
            write: UnsafeCell<[usize; 11]>, // Number of writes completed. The index is the wait count.
        }

        impl FileStat {
            pub fn new() -> Self {
                FileStat {
                    read: UnsafeCell::new([0; 11]),
                    write: UnsafeCell::new([0; 11]),
                }
            }

            pub fn to_string(&self) -> String {
                let read = unsafe { &*self.read.get() };
                let write = unsafe { &*self.write.get() };
                let mut result = String::new();
                result.push_str("File page async read stats: \n");
                let mut sep = "";
                let total_count = read.iter().sum::<usize>();
                let mut cumulative_count = 0;
                for i in 0..11 {
                    result.push_str(sep);
                    cumulative_count += read[i];
                    if i == 10 {
                        result.push_str(&format!(
                            "{:2}+: {:6} (p: {:6.2}%, c: {:6})",
                            i,
                            read[i],
                            read[i] as f64 / total_count as f64 * 100.0,
                            cumulative_count
                        ));
                    } else {
                        result.push_str(&format!(
                            "{:3}: {:6} (p: {:6.2}%, c: {:6})",
                            i,
                            read[i],
                            read[i] as f64 / total_count as f64 * 100.0,
                            cumulative_count
                        ));
                    }
                    sep = "\n";
                }
                result.push_str("\n\n");
                result.push_str("File page async write stats: \n");
                sep = "";
                let total_count = write.iter().sum::<usize>();
                cumulative_count = 0;
                for i in 0..11 {
                    result.push_str(sep);
                    cumulative_count += write[i];
                    if i == 10 {
                        result.push_str(&format!(
                            "{:2}+: {:6} (p: {:6.2}%, c: {:6})",
                            i,
                            write[i],
                            write[i] as f64 / total_count as f64 * 100.0,
                            cumulative_count
                        ));
                    } else {
                        result.push_str(&format!(
                            "{:3}: {:6} (p: {:6.2}%, c: {:6})",
                            i,
                            write[i],
                            write[i] as f64 / total_count as f64 * 100.0,
                            cumulative_count
                        ));
                    }
                    sep = "\n";
                }
                result
            }

            pub fn merge(&self, other: &FileStat) {
                let read = unsafe { &mut *self.read.get() };
                let other_read = unsafe { &*other.read.get() };
                let write = unsafe { &mut *self.write.get() };
                let other_write = unsafe { &*other.write.get() };
                for i in 0..11 {
                    read[i] += other_read[i];
                    write[i] += other_write[i];
                }
            }

            pub fn clear(&self) {
                let read = unsafe { &mut *self.read.get() };
                let write = unsafe { &mut *self.write.get() };
                for i in 0..11 {
                    read[i] = 0;
                    write[i] = 0;
                }
            }
        }

        pub struct LocalStat {
            pub stat: FileStat,
        }

        impl Drop for LocalStat {
            fn drop(&mut self) {
                let global_stat = GLOBAL_FILE_STAT.lock().unwrap();
                global_stat.merge(&self.stat);
            }
        }

        lazy_static! {
            pub static ref GLOBAL_FILE_STAT: Mutex<FileStat> = Mutex::new(FileStat::new());
        }

        thread_local! {
            pub static LOCAL_STAT: LocalStat = LocalStat {
                stat: FileStat::new()
            };
        }

        pub fn inc_local_read_stat(wait_count: usize) {
            LOCAL_STAT.with(|local_stat| {
                let stat = &local_stat.stat;
                let read = unsafe { &mut *stat.read.get() };
                if wait_count >= 10 {
                    read[10] += 1;
                } else {
                    read[wait_count] += 1;
                }
            });
        }

        pub fn inc_local_write_stat(wait_count: usize) {
            LOCAL_STAT.with(|local_stat| {
                let stat = &local_stat.stat;
                let write = unsafe { &mut *stat.write.get() };
                if wait_count >= 10 {
                    write[10] += 1;
                } else {
                    write[wait_count] += 1;
                }
            });
        }
    }

    #[cfg(feature = "stat")]
    use stat::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum IOOp {
        Read,
        Write,
        Flush,
    }

    impl IOOp {
        fn as_u32(&self) -> u32 {
            match self {
                IOOp::Read => 0,
                IOOp::Write => 1,
                IOOp::Flush => 2,
            }
        }
    }

    impl From<u32> for IOOp {
        fn from(op: u32) -> Self {
            match op {
                0 => IOOp::Read,
                1 => IOOp::Write,
                2 => IOOp::Flush,
                _ => panic!("Invalid IOOp"),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct IOOpTag {
        op: IOOp,
        page_id: PageId,
    }

    impl IOOpTag {
        fn get_op(&self) -> IOOp {
            self.op
        }

        fn get_id(&self) -> PageId {
            self.page_id
        }

        fn new_read(page_id: PageId) -> Self {
            IOOpTag {
                op: IOOp::Read,
                page_id,
            }
        }

        fn new_write(page_id: PageId) -> Self {
            IOOpTag {
                op: IOOp::Write,
                page_id,
            }
        }

        fn new_flush() -> Self {
            IOOpTag {
                op: IOOp::Flush,
                page_id: PageId::MAX,
            }
        }

        fn as_u64(&self) -> u64 {
            let upper_32 = self.op.as_u32() as u64;
            let lower_32 = self.page_id as u64;
            (upper_32 << 32) | lower_32
        }
    }

    impl From<u64> for IOOpTag {
        fn from(tag: u64) -> Self {
            let upper_32 = (tag >> 32) as u32;
            let lower_32 = tag as u32;
            IOOpTag {
                op: IOOp::from(upper_32),
                page_id: lower_32,
            }
        }
    }

    unsafe impl Send for FileManagerInner {} // Send is needed for io_vec

    struct FileManagerInner {
        _file: File,
        ring: IoUring,
        page_buffer_status: Vec<bool>, // Written = true, Not written = false
        page_buffer: Vec<Page>,
        _io_vec: UnsafeCell<Vec<iovec>>, // We have to keep this in-memory for the lifetime of the io_uring.
    }

    impl FileManagerInner {
        fn new(file: File) -> Result<Self, std::io::Error> {
            let ring = IoUring::builder()
                .setup_sqpoll(1)
                .build(PAGE_BUFFER_SIZE as _)?;
            let mut page_buffer: Vec<Page> = (0..PAGE_BUFFER_SIZE)
                .map(|_| Page::new(PageId::MAX))
                .collect();
            let io_vec = page_buffer
                .iter_mut()
                .map(|page| iovec {
                    iov_base: page.get_raw_bytes_mut().as_mut_ptr() as _,
                    iov_len: PAGE_SIZE as _,
                })
                .collect::<Vec<_>>();
            // Register the file and the page buffer with the io_uring.
            let submitter = &ring.submitter();
            submitter.register_files(&[file.as_raw_fd()])?;
            unsafe {
                submitter.register_buffers(&io_vec)?;
            }
            Ok(FileManagerInner {
                _file: file,
                ring,
                page_buffer_status: (0..PAGE_BUFFER_SIZE).map(|_| true).collect(),
                page_buffer,
                _io_vec: UnsafeCell::new(io_vec),
            })
        }

        fn compute_hash(page_id: PageId) -> usize {
            // For safety, we take the Rust std::hash function
            // instead of a simple page_id as usize % PAGE_BUFFER_SIZE
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            page_id.hash(&mut hasher);
            hasher.finish() as usize % PAGE_BUFFER_SIZE
        }

        fn read_page(&mut self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {
            // Check the entry in the page_buffer
            let hash = FileManagerInner::compute_hash(page_id);
            let mut _count = 0;
            if page_id == self.page_buffer[hash].get_id() {
                page.copy(&self.page_buffer[hash]);
            } else {
                // If the page is not in the buffer, read from the file.
                let buf = page.get_raw_bytes_mut();
                let entry = opcode::Read::new(types::Fixed(0), buf.as_mut_ptr(), buf.len() as _)
                    .offset(page_id as u64 * PAGE_SIZE as u64)
                    .build()
                    .user_data(IOOpTag::new_read(page_id).as_u64());
                unsafe {
                    self.ring.submission().push(&entry).expect("queue is full");
                }
                let _res = self.ring.submit()?;
                // assert_eq!(res, 1); // This is true if SQPOLL is disabled.

                loop {
                    if let Some(entry) = self.ring.completion().next() {
                        let tag = IOOpTag::from(entry.user_data());
                        _count += 1;
                        match tag.get_op() {
                            IOOp::Read => {
                                // Reads are run in sequence, so this should be the page we are interested in.
                                assert_eq!(tag.get_id(), page_id);
                                break;
                            }
                            IOOp::Write => {
                                let this_page_id = tag.get_id();
                                let this_hash = FileManagerInner::compute_hash(this_page_id);
                                self.page_buffer_status[this_hash] = true; // Mark the page as written.
                            }
                            IOOp::Flush => {
                                // Do nothing
                            }
                        }
                    } else {
                        std::hint::spin_loop();
                    }
                }
            }

            log_debug!(
                "Read completed for page: {} with wait count: {}",
                page_id,
                _count
            );
            #[cfg(feature = "stat")]
            inc_local_read_stat(_count);
            Ok(())
        }

        fn write_page(&mut self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            // Check the entry in the page_buffer
            let hash = FileManagerInner::compute_hash(page_id);
            let mut _count = 0;
            loop {
                // Check the status of the page buffer.
                if self.page_buffer_status[hash] {
                    // If the page is written, overwrite the page and issue an async write.
                    self.page_buffer_status[hash] = false; // Mark the page as not written.
                    self.page_buffer[hash].copy(page);
                    let buf = self.page_buffer[hash].get_raw_bytes();
                    let entry = opcode::WriteFixed::new(
                        types::Fixed(0),
                        buf.as_ptr(),
                        buf.len() as _,
                        hash as _,
                    )
                    .offset(page_id as u64 * PAGE_SIZE as u64)
                    .build()
                    .user_data(IOOpTag::new_write(page_id).as_u64());
                    unsafe {
                        self.ring.submission().push(&entry).expect("queue is full");
                    }
                    let _res = self.ring.submit()?;
                    // assert_eq!(res, 1); // This is true if SQPOLL is disabled.
                    log_debug!(
                        "Write completed for page: {} with wait count: {}",
                        page_id,
                        _count
                    );
                    #[cfg(feature = "stat")]
                    inc_local_write_stat(_count);
                    return Ok(()); // This is the only return point.
                } else {
                    // If the page is not written, wait for the write to complete.
                    loop {
                        if let Some(entry) = self.ring.completion().next() {
                            _count += 1;
                            let tag = IOOpTag::from(entry.user_data());
                            match tag.get_op() {
                                IOOp::Write => {
                                    let this_page_id = tag.get_id();
                                    let this_hash = FileManagerInner::compute_hash(this_page_id);
                                    self.page_buffer_status[this_hash] = true; // Mark the page as written.
                                    if this_hash == hash {
                                        break; // Write completed for the buffer we are interested in.
                                    }
                                }
                                IOOp::Flush => {
                                    // Do nothing
                                }
                                IOOp::Read => {
                                    // Read should run synchronously, so this should not happen.
                                    panic!("Read should not be completed while waiting for write")
                                }
                            }
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                }
            }
        }

        fn flush(&mut self) -> Result<(), std::io::Error> {
            // Find the first entry in the page_buffer that is not written. Wait for it to be written.
            for i in 0..PAGE_BUFFER_SIZE {
                if !self.page_buffer_status[i] {
                    let mut _count = 0;
                    loop {
                        if let Some(entry) = self.ring.completion().next() {
                            _count += 1;
                            let tag = IOOpTag::from(entry.user_data());
                            match tag.get_op() {
                                IOOp::Write => {
                                    let this_page_id = tag.get_id();
                                    let this_hash = FileManagerInner::compute_hash(this_page_id);
                                    self.page_buffer_status[this_hash] = true; // Mark the page as written.
                                    if this_hash == i {
                                        break; // Write completed for the buffer we are interested in.
                                    }
                                }
                                IOOp::Flush => {
                                    // Do nothing
                                }
                                IOOp::Read => {
                                    // Read should run synchronously, so this should not happen.
                                    panic!("Read should not be completed while waiting for write")
                                }
                            }
                        } else {
                            std::hint::spin_loop();
                        }
                    }
                }
            }
            assert!(self.page_buffer_status.iter().all(|&x| x));
            // Now issue a flush operation.
            let entry = opcode::Fsync::new(types::Fixed(0))
                .build()
                .user_data(IOOpTag::new_flush().as_u64());
            unsafe {
                self.ring.submission().push(&entry).expect("queue is full");
            }
            let res = self.ring.submit_and_wait(1)?;
            assert_eq!(res, 1);

            // Check the completion queue for the flush operation.
            let entry = self.ring.completion().next().unwrap();
            let tag = IOOpTag::from(entry.user_data());
            assert_eq!(tag.get_op(), IOOp::Flush);

            Ok(())
        }
    }
}

mod new_async_write {
    use super::ContainerId;
    #[allow(unused_imports)]
    use crate::log;
    use crate::page::{Page, PageId, PAGE_SIZE};
    use crate::rwlatch::RwLatch;

    use std::cell::UnsafeCell;
    use std::fs::{File, OpenOptions};

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    use io_uring::{opcode, types, IoUring};

    use std::hash::{Hash, Hasher};
    use std::os::unix::io::AsRawFd;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum IOOp {
        Read,
        Write,
        Flush,
    }

    impl IOOp {
        fn as_u32(&self) -> u32 {
            match self {
                IOOp::Read => 0,
                IOOp::Write => 1,
                IOOp::Flush => 2,
            }
        }
    }

    impl From<u32> for IOOp {
        fn from(op: u32) -> Self {
            match op {
                0 => IOOp::Read,
                1 => IOOp::Write,
                2 => IOOp::Flush,
                _ => panic!("Invalid IOOp"),
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct IOOpTag {
        op: IOOp,
        page_id: PageId,
    }

    impl IOOpTag {
        fn get_op(&self) -> IOOp {
            self.op
        }

        fn get_id(&self) -> PageId {
            self.page_id
        }

        fn new_read(page_id: PageId) -> Self {
            IOOpTag {
                op: IOOp::Read,
                page_id,
            }
        }

        fn new_write(page_id: PageId) -> Self {
            IOOpTag {
                op: IOOp::Write,
                page_id,
            }
        }

        fn new_flush() -> Self {
            IOOpTag {
                op: IOOp::Flush,
                page_id: PageId::MAX,
            }
        }

        fn as_u64(&self) -> u64 {
            let upper_32 = self.op.as_u32() as u64;
            let lower_32 = self.page_id as u64;
            (upper_32 << 32) | lower_32
        }
    }

    impl From<u64> for IOOpTag {
        fn from(tag: u64) -> Self {
            let upper_32 = (tag >> 32) as u32;
            let lower_32 = tag as u32;
            IOOpTag {
                op: IOOp::from(upper_32),
                page_id: lower_32,
            }
        }
    }

    const PAGE_BUFFER_SIZE: usize = 128;

    pub struct FileManager {
        _file: File,
        num_pages: AtomicU32,
        ring: Mutex<IoUring>,
        page_buffer: Vec<(UnsafeCell<Page>, AtomicU32, RwLatch)>, // (Page, Status, Latch) // Status: 0 = no on-going work, 1 = on-going work
    }

    unsafe impl Sync for FileManager {}

    impl FileManager {
        pub fn new<P: AsRef<std::path::Path>>(
            db_dir: P,
            c_id: ContainerId,
        ) -> Result<Self, std::io::Error> {
            std::fs::create_dir_all(&db_dir)?;
            let path = db_dir.as_ref().join(format!("{}", c_id));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)?;
            let num_pages = file.metadata().unwrap().len() as usize / PAGE_SIZE;

            let ring = IoUring::builder()
                .setup_sqpoll(1)
                .build(PAGE_BUFFER_SIZE as _)?;
            let page_buffer: Vec<(UnsafeCell<Page>, AtomicU32, RwLatch)> = (0..PAGE_BUFFER_SIZE)
                .map(|_| {
                    let page = UnsafeCell::new(Page::new(PageId::MAX));
                    (page, AtomicU32::new(0), RwLatch::default())
                })
                .collect();
            // Register the file and the page buffer with the io_uring.
            let submitter = &ring.submitter();
            submitter.register_files(&[file.as_raw_fd()])?;

            Ok(FileManager {
                _file: file,
                num_pages: AtomicU32::new(num_pages as PageId),
                ring: Mutex::new(ring),
                page_buffer,
            })
        }

        pub fn fetch_add_page_id(&self) -> PageId {
            self.num_pages.fetch_add(1, Ordering::AcqRel)
        }

        pub fn fetch_sub_page_id(&self) -> PageId {
            self.num_pages.fetch_sub(1, Ordering::AcqRel)
        }

        #[allow(dead_code)]
        pub fn get_stats(&self) -> String {
            format!("Num pages: {}", self.num_pages.load(Ordering::Acquire),)
        }

        fn compute_hash(page_id: PageId) -> usize {
            // For safety, we take the Rust std::hash function
            // instead of a simple page_id as usize % PAGE_BUFFER_SIZE
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            page_id.hash(&mut hasher);
            hasher.finish() as usize % PAGE_BUFFER_SIZE
        }

        fn poll_once(&self) {
            if let Some(entry) = self.ring.lock().unwrap().completion().next() {
                let tag = IOOpTag::from(entry.user_data());
                match tag.get_op() {
                    IOOp::Read => {
                        let page_id = tag.get_id();
                        let hash = FileManager::compute_hash(page_id);
                        self.page_buffer[hash].1.store(0, Ordering::Release); // Mark the page as no on-going work.
                    }
                    IOOp::Write => {
                        let page_id = tag.get_id();
                        let hash = FileManager::compute_hash(page_id);
                        self.page_buffer[hash].1.store(0, Ordering::Release); // Mark the page as no on-going work.
                    }
                    IOOp::Flush => {
                        // Do nothing
                    }
                }
            }
        }

        pub fn prefetch_page(&self, page_id: PageId) -> Result<(), std::io::Error> {
            let hash = FileManager::compute_hash(page_id);
            let (buffer, status, latch) = &self.page_buffer[hash];
            let buffer = unsafe { &mut *buffer.get() };

            // Latch the page for loading the page from disk to buffer.
            while !latch.try_exclusive() {
                self.poll_once();
            }

            // While there is on-going work on the page, wait.
            while status.swap(1, Ordering::AcqRel) == 1 {
                self.poll_once();
            }

            // Now, the page has no on-going work.
            if buffer.get_id() == page_id {
                status.store(0, Ordering::Release); // Mark the page as no on-going work.
                latch.release_exclusive();
                Ok(())
            } else {
                // Issue a read operation to the file.
                let buf = buffer.get_raw_bytes_mut();
                let entry = opcode::Read::new(types::Fixed(0), buf.as_mut_ptr(), buf.len() as _)
                    .offset(page_id as u64 * PAGE_SIZE as u64)
                    .build()
                    .user_data(IOOpTag::new_read(page_id).as_u64());
                let ring = &mut *self.ring.lock().unwrap();
                unsafe { ring.submission().push(&entry).expect("queue is full") };
                let _res = ring.submit()?;
                // assert_eq!(res, 1); // This is true if SQPOLL is disabled.

                latch.release_exclusive();
                // The status is kept as 1, to tell that the buffer is currently being used for prefetching.
                Ok(())
            }
        }

        pub fn read_page(&self, page_id: PageId, page: &mut Page) -> Result<(), std::io::Error> {
            // Check the entry in the page_buffer
            let hash = FileManager::compute_hash(page_id);
            let (buffer, status, latch) = &self.page_buffer[hash];
            let buffer = unsafe { &*buffer.get() };

            // Latch the page for loading.
            while !latch.try_exclusive() {
                self.poll_once();
            }

            // While there is on-going work on the page, wait.
            while status.swap(1, Ordering::AcqRel) == 1 {
                self.poll_once();
            }

            // Now, the page has no on-going work.
            if buffer.get_id() == page_id {
                // println!("Direct read");
                page.copy(buffer);
                status.store(0, Ordering::Release); // Mark the page as no on-going work.
                latch.release_exclusive();
                Ok(())
            } else {
                // println!("Indirect read");
                // The page is not in the buffer.
                // Since no one else is working on page, we can issue the read operation to the file.
                let buf = page.get_raw_bytes_mut();
                let entry = opcode::Read::new(types::Fixed(0), buf.as_mut_ptr(), buf.len() as _)
                    .offset(page_id as u64 * PAGE_SIZE as u64)
                    .build()
                    .user_data(IOOpTag::new_read(page_id).as_u64());
                {
                    let ring = &mut self.ring.lock().unwrap();
                    unsafe { ring.submission().push(&entry).expect("queue is full") };
                    let _res = ring.submit()?;
                }

                // Poll the completion queue until the read operation is completed.
                while status.load(Ordering::Acquire) == 1 {
                    self.poll_once();
                }

                // The read operation is completed. The page contains the buffer now.
                // Note that buffer is not updated.
                // assert_eq!(page.get_id(), page_id); This is usually true but in some tests, page_id is not set.
                latch.release_exclusive();
                Ok(())
            }
        }

        pub fn write_page(&self, page_id: PageId, page: &Page) -> Result<(), std::io::Error> {
            // Check the entry in the page_buffer
            let hash = FileManager::compute_hash(page_id);
            let (buffer, status, latch) = &self.page_buffer[hash];
            let buffer = unsafe { &mut *buffer.get() };

            // Latch the page for writing.
            while !latch.try_exclusive() {
                self.poll_once();
            }

            // While there is on-going work on the page, wait.
            while status.swap(1, Ordering::AcqRel) == 1 {
                self.poll_once();
            }

            buffer.copy(page);
            let buf = buffer.get_raw_bytes();
            let entry = opcode::Write::new(types::Fixed(0), buf.as_ptr(), buf.len() as _)
                .offset(page_id as u64 * PAGE_SIZE as u64)
                .build()
                .user_data(IOOpTag::new_write(page_id).as_u64());

            let ring = &mut *self.ring.lock().unwrap();
            unsafe { ring.submission().push(&entry).expect("queue is full") };
            let _res = ring.submit()?;
            // assert_eq!(res, 1); // This is true if SQPOLL is disabled.

            // Release the latch
            latch.release_exclusive();

            Ok(()) // This is the only return point.
        }

        pub fn flush(&self) -> Result<(), std::io::Error> {
            // Find the first entry in the page_buffer that is not written. Wait for it to be written.
            for i in 0..PAGE_BUFFER_SIZE {
                let (_, status, latch) = &self.page_buffer[i];
                while !latch.try_exclusive() {
                    self.poll_once();
                }

                while status.load(Ordering::Acquire) == 1 {
                    self.poll_once();
                }

                latch.release_exclusive();
            }

            // Now issue a flush operation.
            // let entry = opcode::Fsync::new(types::Fixed(0))
            //     .build()
            //     .user_data(IOOpTag::new_flush().as_u64());
            // let ring = &mut *self.ring.lock().unwrap();
            // unsafe { ring.submission().push(&entry).expect("queue is full") };
            // let _res = ring.submit()?;

            // Issue a sync flush
            self._file.sync_all()?;

            Ok(())
        }
    }
}
*/

#[cfg(test)]
mod tests {
    use super::FileManager;
    use crate::page::{Page, PageId};
    use crate::random::gen_random_permutation;

    #[test]
    fn test_page_write_read() {
        let temp_path = tempfile::tempdir().unwrap();
        let file_manager = FileManager::new(&temp_path, 0).unwrap();
        let mut page = Page::new_empty();

        let page_id = 0;
        page.set_id(page_id);

        let data = b"Hello, World!";
        page[0..data.len()].copy_from_slice(data);

        file_manager.write_page(page_id, &page).unwrap();

        let mut read_page = Page::new_empty();
        file_manager.read_page(page_id, &mut read_page).unwrap();

        assert_eq!(&read_page[0..data.len()], data);
    }

    #[test]
    fn test_prefetch() {
        let temp_path = tempfile::tempdir().unwrap();
        let file_manager = FileManager::new(&temp_path, 0).unwrap();

        let num_pages = 1000;
        let page_id_vec = (0..num_pages).collect::<Vec<PageId>>();

        // Write the pages
        for i in 0..num_pages {
            let mut page = Page::new_empty();
            page.set_id(i);

            let data = format!("Hello, World! {}", i);
            page[0..data.len()].copy_from_slice(data.as_bytes());

            file_manager.write_page(i, &page).unwrap();
        }

        for i in gen_random_permutation(page_id_vec) {
            file_manager.prefetch_page(i).unwrap();
            let mut read_page = Page::new_empty();
            file_manager.read_page(i, &mut read_page).unwrap();
        }
    }

    #[test]
    fn test_page_write_read_sequential() {
        let temp_path = tempfile::tempdir().unwrap();
        let file_manager = FileManager::new(&temp_path, 0).unwrap();

        let num_pages = 1000;

        for i in 0..num_pages {
            let mut page = Page::new_empty();
            page.set_id(i);

            let data = format!("Hello, World! {}", i);
            page[0..data.len()].copy_from_slice(data.as_bytes());

            file_manager.write_page(i, &page).unwrap();
        }

        for i in 0..num_pages {
            let mut read_page = Page::new_empty();
            file_manager.read_page(i, &mut read_page).unwrap();

            let data = format!("Hello, World! {}", i);
            assert_eq!(&read_page[0..data.len()], data.as_bytes());
        }
    }

    #[test]
    fn test_page_write_read_random() {
        let temp_path = tempfile::tempdir().unwrap();
        let file_manager = FileManager::new(&temp_path, 0).unwrap();

        let num_pages = 1000;
        let page_id_vec = (0..num_pages).collect::<Vec<PageId>>();

        // Write the page in random order
        for i in gen_random_permutation(page_id_vec.clone()) {
            let mut page = Page::new_empty();
            page.set_id(i);

            let data = format!("Hello, World! {}", i);
            page[0..data.len()].copy_from_slice(data.as_bytes());

            file_manager.write_page(i, &page).unwrap();
        }

        // Read the page in random order
        for i in gen_random_permutation(page_id_vec) {
            let mut read_page = Page::new_empty();
            file_manager.read_page(i, &mut read_page).unwrap();

            let data = format!("Hello, World! {}", i);
            assert_eq!(&read_page[0..data.len()], data.as_bytes());
        }
    }

    #[test]
    fn test_page_write_read_interleave() {
        let temp_path = tempfile::tempdir().unwrap();
        let file_manager = FileManager::new(&temp_path, 0).unwrap();

        let num_pages = 1000;
        let page_id_vec = (0..num_pages).collect::<Vec<PageId>>();

        // Write the page in random order
        for i in gen_random_permutation(page_id_vec.clone()) {
            let mut page = Page::new_empty();
            page.set_id(i);

            let data = format!("Hello, World! {}", i);
            page[0..data.len()].copy_from_slice(data.as_bytes());

            file_manager.write_page(i, &page).unwrap();

            let mut read_page = Page::new_empty();
            file_manager.read_page(i, &mut read_page).unwrap();

            assert_eq!(&read_page[0..data.len()], data.as_bytes());
        }
    }

    #[test]
    fn test_file_flush() {
        // Create two file managers with the same path.
        // Issue multiple write operations to one of the file managers.
        // Check if the other file manager can read the pages.

        let temp_path = tempfile::tempdir().unwrap();
        let file_manager1 = FileManager::new(&temp_path, 0).unwrap();
        let file_manager2 = FileManager::new(&temp_path, 0).unwrap();

        let num_pages = 2;
        let page_id_vec = (0..num_pages).collect::<Vec<PageId>>();

        // Write the page in random order
        for i in gen_random_permutation(page_id_vec.clone()) {
            let mut page = Page::new_empty();
            page.set_id(i);

            let data = format!("Hello, World! {}", i);
            page[0..data.len()].copy_from_slice(data.as_bytes());

            file_manager1.write_page(i, &page).unwrap();
        }

        file_manager1.flush().unwrap(); // If we remove this line, the test is likely to fail.

        // Read the page in random order
        for i in gen_random_permutation(page_id_vec) {
            let mut read_page = Page::new_empty();
            file_manager2.read_page(i, &mut read_page).unwrap();

            let data = format!("Hello, World! {}", i);
            assert_eq!(&read_page[0..data.len()], data.as_bytes());
        }
    }

    #[test]
    fn test_concurrent_read_write_file() {
        let temp_path = tempfile::tempdir().unwrap();
        let file_manager = FileManager::new(&temp_path, 0).unwrap();

        let num_pages = 1000;
        let page_id_vec = (0..num_pages).collect::<Vec<PageId>>();

        let num_threads = 2;

        // Partition the page_id_vec into num_threads partitions.
        let partitions: Vec<Vec<PageId>> = {
            let mut partitions = vec![];
            let partition_size = num_pages / num_threads;
            for i in 0..num_threads {
                let start = (i * partition_size) as usize;
                let end = if i == num_threads - 1 {
                    num_pages
                } else {
                    (i + 1) * partition_size
                } as usize;
                partitions.push(page_id_vec[start..end].to_vec());
            }
            partitions
        };

        std::thread::scope(|s| {
            for partition in partitions.clone() {
                s.spawn(|| {
                    for i in gen_random_permutation(partition) {
                        let mut page = Page::new_empty();
                        page.set_id(i);

                        let data = format!("Hello, World! {}", i);
                        page[0..data.len()].copy_from_slice(data.as_bytes());

                        file_manager.write_page(i, &page).unwrap();
                    }
                });
            }
        });

        // Issue concurrent read
        std::thread::scope(|s| {
            for partition in partitions {
                s.spawn(|| {
                    for i in gen_random_permutation(partition) {
                        let mut read_page = Page::new_empty();
                        file_manager.read_page(i, &mut read_page).unwrap();

                        let data = format!("Hello, World! {}", i);
                        assert_eq!(&read_page[0..data.len()], data.as_bytes());
                    }
                });
            }
        });
    }
}
