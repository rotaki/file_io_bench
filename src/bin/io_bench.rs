use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use file_io_bench::file_manager::FileManager;
use file_io_bench::page::{Page, PageId, PAGE_SIZE};
use file_io_bench::random::gen_random_int;

#[derive(Parser, Clone)]
pub struct IOBench {
    #[clap(short, long, default_value = "1")]
    num_threads: usize,
    #[clap(short, long, default_value = "1048576")]
    file_size: usize, // in multiples of page size
    #[clap(short, long, default_value = "10")]
    duration: u64,
}

impl std::fmt::Display for IOBench {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IOBench {{ num_threads: {}, file_size: {}, duration: {} }}",
            self.num_threads, self.file_size, self.duration
        )
    }
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

/// Thread-local stats now use an atomic counter for writes.
pub struct ThreadLocalStats {
    pub thread_id: usize,
    pub write_count: AtomicUsize,
}

/// Initializes the file by writing one page per index in parallel.
/// The file is wrapped in an `Arc` so it can be shared across threads.
/// The work is partitioned into `num_threads` ranges.
pub fn initialize_file(file_size: usize, file: &Arc<FileManager>, num_threads: usize) {
    println!(
        "Initializing file with {} pages using {} threads...",
        file_size, num_threads
    );

    // Calculate the number of pages per thread and any remainder.
    let pages_per_thread = file_size / num_threads;
    let remainder = file_size % num_threads;

    let mut handles = Vec::with_capacity(num_threads);

    for thread_index in 0..num_threads {
        let file_clone = Arc::clone(file);

        // Determine the start and end indices for this thread.
        let start = thread_index * pages_per_thread + thread_index.min(remainder);
        let mut end = start + pages_per_thread;
        if thread_index < remainder {
            // Distribute the remainder among the first few threads.
            end += 1;
        }

        let handle = thread::spawn(move || {
            for i in start..end {
                let page = Page::new(i as PageId);
                file_clone.write_page(i as PageId, &page).unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all initialization threads to finish.
    for handle in handles {
        handle
            .join()
            .expect("Thread panicked during initialization");
    }

    println!("File initialized.");
}

/// The measured execution loop that performs only disk writes.
/// The thread-local data (td) is used for any thread-specific data, and
/// ts is used to update the atomic write counter.
pub fn per_thread_write_execution(
    flag: &AtomicBool,
    args: &IOBench,
    file: &FileManager,
    td: &mut ThreadLocalData,
    ts: &ThreadLocalStats,
) {
    // This loop is the measured part: performing disk writes.
    while !flag.load(Ordering::Relaxed) {
        // Choose a random page ID.
        let page_id = (gen_random_int(0, args.file_size as PageId - 1)) as PageId;
        td.page.set_id(page_id);
        // Write the page to disk.
        file.write_page(page_id as PageId, &td.page).unwrap();
        // Update the thread's write counter atomically.
        ts.write_count.fetch_add(1, Ordering::Relaxed);
        // Sleep a bit to avoid saturating the system.
        // thread::sleep(Duration::from_millis(10));
    }
}

fn main() {
    // Parse command line arguments.
    let args: IOBench = IOBench::parse();
    println!("Page size: {} KiB", PAGE_SIZE / 1024);
    println!("Arguments: {}", args);

    // Create (or open) the file and wrap it in an Arc.
    let file = Arc::new(FileManager::new(".", 0).unwrap());

    // Initialize the file on disk (this work is not measured).
    initialize_file(args.file_size, &file, 4);

    // Create a barrier so that all threads start the measured loop at the same time.
    let barrier = Arc::new(Barrier::new(args.num_threads));
    // Create a flag that signals threads to stop.
    let flag = Arc::new(AtomicBool::new(false));

    // Create a vector to hold each thread's stats.
    let mut stats_vec = Vec::new();
    // Vector to hold thread join handles.
    let mut handles = Vec::new();

    // Spawn worker threads.
    for i in 0..args.num_threads {
        let barrier_clone = Arc::clone(&barrier);
        let flag_clone = Arc::clone(&flag);
        let args_clone = args.clone();
        let file_clone = Arc::clone(&file);
        // Create per-thread atomic stats.
        let ts = Arc::new(ThreadLocalStats {
            thread_id: i,
            write_count: AtomicUsize::new(0),
        });
        // Save a clone of the Arc so the main thread can monitor stats.
        stats_vec.push(Arc::clone(&ts));

        let handle = thread::spawn(move || {
            // Phase 1: Thread-local initialization (not measured)
            let mut td = ThreadLocalData::new(i);

            // Wait until all threads are ready.
            barrier_clone.wait();

            // Phase 2: Measured disk writes.
            per_thread_write_execution(&flag_clone, &args_clone, &file_clone, &mut td, &ts);
        });
        handles.push(handle);
    }

    // Measurement: Main thread prints bandwidth every 2 seconds.
    // We'll measure for a total of 10 seconds.
    let measurement_duration = Duration::from_secs(args.duration);
    let measurement_interval = Duration::from_secs(2);
    let page_size = 4096; // in bytes
    let start_time = Instant::now();
    let mut last_total_writes = 0;

    while start_time.elapsed() < measurement_duration {
        thread::sleep(measurement_interval);

        // Sum up the total writes from all threads.
        let total_writes: usize = stats_vec
            .iter()
            .map(|ts| ts.write_count.load(Ordering::Relaxed))
            .sum();
        let delta_writes = total_writes - last_total_writes;
        last_total_writes = total_writes;
        // Calculate bandwidth (bytes/sec).
        let bandwidth = (delta_writes * page_size) as f64 / measurement_interval.as_secs_f64();
        println!(
            "Current bandwidth: {:.2} MiB/sec",
            bandwidth / 1024.0 / 1024.0
        );
    }

    // Signal threads to stop.
    flag.store(true, Ordering::Relaxed);

    // Wait for all threads to finish.
    for handle in handles {
        handle.join().unwrap();
    }

    // Print final total writes.
    let total_writes: usize = stats_vec
        .iter()
        .map(|ts| ts.write_count.load(Ordering::Relaxed))
        .sum();
    println!("Final total writes = {}", total_writes);
    println!(
        "Final bandwidth = {:.2} MiB/sec",
        (total_writes * page_size) as f64 / 1024.0 / 1024.0 / args.duration as f64
    );
}
