use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use clap::Parser;
use file_io_bench::file_manager::FileManager;
use file_io_bench::page::{Page, PageId, PAGE_SIZE};
use file_io_bench::random::gen_random_int;

#[derive(Parser, Clone)]
pub struct IOBench {
    #[clap(short, long, default_value = "1")]
    // Number of threads.
    num_threads: usize,
    #[clap(short, long, default_value = "10")]
    // Duration in seconds.
    duration: u64,
    #[clap(short, long, default_value = "1048576")]
    // File size in pages. Default is 1 million pages.
    file_size: usize,
}

pub struct ThreadLocalData {
    pub thread_id: usize,
    pub page: Page,
}

impl ThreadLocalData {
    pub fn new(thread_id: usize) -> Self {
        ThreadLocalData {
            thread_id,
            page: Page::new_empty(),
        }
    }
}

pub struct ThreadLocalStats {
    pub thread_id: usize,
    pub write_count: usize,
}

/// Initializes the file by writing one page per index.
/// The file is passed as a reference.
pub fn initialize_file(file_size: usize, file: &FileManager) {
    for i in 0..file_size {
        let page = Page::new(i as PageId);
        file.write_page(i as PageId, &page).unwrap();
    }
}

/// The measured execution loop that performs only disk writes.
/// The thread-local data (td) and stats (ts) are passed as mutable references.
pub fn per_thread_write_execution(
    flag: &AtomicBool,
    args: &IOBench,
    file: &FileManager,
    td: &mut ThreadLocalData,
    ts: &mut ThreadLocalStats,
) {
    // This loop performs only disk writes (measured)
    while !flag.load(Ordering::Relaxed) {
        // Choose a random page ID in the file.
        let page_id = gen_random_int(0, args.file_size - 1) as PageId;
        td.page.set_id(page_id);
        // Write the page to disk.
        file.write_page(page_id as PageId, &td.page).unwrap();
        // Update thread-local stats.
        ts.write_count += 1;
        // Optionally sleep a bit to avoid saturating the system.
        thread::sleep(Duration::from_millis(10));
    }
}

fn main() {
    // Parse command line arguments.
    let args: IOBench = IOBench::parse();

    // Create (or open) the file and wrap it in an Arc.
    let file = Arc::new(FileManager::new(".", 0).unwrap());

    // Initialize the file on disk (this work is not measured).
    initialize_file(args.file_size, &file);

    // Create a barrier so that all threads start the measurement loop at the same time.
    let barrier = Arc::new(Barrier::new(args.num_threads));
    // Create a flag that signals threads to stop.
    let flag = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    // Spawn threads.
    for i in 0..args.num_threads {
        let barrier_clone = Arc::clone(&barrier);
        let flag_clone = Arc::clone(&flag);
        let args_clone = args.clone();
        let file_clone = Arc::clone(&file);
        let handle = thread::spawn(move || {
            // Phase 1: Thread-local initialization (not measured)
            let mut td = ThreadLocalData::new(i);
            let mut ts = ThreadLocalStats {
                thread_id: i,
                write_count: 0,
            };

            // Wait until all threads have finished initialization.
            barrier_clone.wait();

            // Phase 2: Measured execution of disk writes.
            per_thread_write_execution(&flag_clone, &args_clone, &file_clone, &mut td, &mut ts);

            // Return the thread's stats.
            ts
        });
        handles.push(handle);
    }

    // Let the threads run for 3 seconds (measured pure writes).
    thread::sleep(Duration::from_secs(args.duration));
    // Signal all threads to stop.
    flag.store(true, Ordering::Relaxed);

    // Wait for threads to finish and gather their statistics.
    let mut total_writes = 0;
    for handle in handles {
        let stats = handle.join().unwrap();
        println!("Thread {}: writes = {}", stats.thread_id, stats.write_count);
        total_writes += stats.write_count;
    }
    println!("Total writes = {}", total_writes);
    println!(
        "Bandwidth = {:.2} MiB/s",
        total_writes as f64 * PAGE_SIZE as f64 / 1024.0 / 1024.0 / args.duration as f64
    );
}
