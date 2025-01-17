/* SPDX-License-Identifier: BSD-3-Clause */
/*******************************************************************************
 * Copyright 2024-2025 Fraunhofer SIT, sponsored by the ELISA research project.
 * All rights reserved.
 ******************************************************************************/

use const_random::const_random;
use log::{debug, info, trace};
use regex::{Regex, RegexBuilder};
use std::{
    env, fs,
    net::{IpAddr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Mutex, MutexGuard, Once, OnceLock},
    time::{Duration, Instant},
};
use uuid::Uuid;

/* Defaults */
const TCTI_DEFAULT_VALUE: &str = "swtpm:host=127.0.0.1,port=2321";
const PROF_DEFAULT_VALUE: &str = "RSA2048SHA256";

/* One-time initialization */
static ENV_LOGGER_INIT: Once = Once::new();

/* Lazy initialization of Regex */
static REGEX_SWTPM: OnceLock<Regex> = OnceLock::new();

/* Randomize (at compile-time!) */
const RANDOM_UUID_PREFIX: Uuid = Uuid::from_u64_pair(const_random!(u64), const_random!(u64));

/* Finalizer type alias */
type Finalizer = Box<dyn FnOnce() + 'static>;

/* The mutex lock */
static MUTEX: Mutex<bool> = Mutex::new(false);

/* Accquire the lock */
macro_rules! accquire_lock {
    ($mutex:ident, $lock:ident) => {
        let mut $lock = $mutex.lock().or_else(|err| Ok::<_, ()>(err.into_inner())).unwrap();
        assert_eq!(*$lock, false);
        *$lock = true;
    };
}

pub struct TestConfiguration<'a> {
    uniq_lock: MutexGuard<'a, bool>,
    prof_name: &'a str,
    data_path: PathBuf,
    work_path: PathBuf,
    finalizer: Option<Finalizer>,
}

impl Default for TestConfiguration<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TestConfiguration<'a> {
    pub fn new() -> Self {
        accquire_lock!(MUTEX, uniq_lock);
        ENV_LOGGER_INIT.call_once(env_logger::init);
        Self::initialize(uniq_lock, None)
    }

    pub fn with_finalizer(finalizer: impl FnOnce() + 'static) -> Self {
        accquire_lock!(MUTEX, uniq_lock);
        ENV_LOGGER_INIT.call_once(env_logger::init);
        Self::initialize(uniq_lock, Some(Box::new(finalizer)))
    }

    fn initialize(uniq_lock: MutexGuard<'a, bool>, finalizer: Option<Finalizer>) -> Self {
        info!("Setting up the FAPI configuration, please wait...");

        if let Some(path) = option_env!("FAPI_RS_TEST_DIR") {
            env::set_current_dir(Path::new(path)).expect("Failed to set the working directory!");
        }

        let tcti_conf = option_env!("FAPI_RS_TEST_TCTI").unwrap_or(TCTI_DEFAULT_VALUE);
        let prof_name = option_env!("FAPI_RS_TEST_PROF").unwrap_or(PROF_DEFAULT_VALUE);

        let regex_swtpm = REGEX_SWTPM.get_or_init(|| {
            RegexBuilder::new(r"^\s*swtpm\s*:\s*host\s*=\s*([^\s,]+)\s*,\s*port\s*=\s*([^\s,]+)")
                .case_insensitive(true)
                .build()
                .unwrap()
        });

        if let Some(capture) = regex_swtpm.captures(tcti_conf) {
            let (host, port) = (capture.get(1).unwrap().as_str(), capture.get(2).unwrap().as_str().parse::<u16>().unwrap());
            Self::check_tpm_connection(host, port);
        }

        let base_path = Path::new(env!("CARGO_MANIFEST_DIR"));
        debug!("Base directory: \"{}\"", base_path.to_str().unwrap());

        let data_path = base_path.join("tests").join("data");
        debug!("Data directory: \"{}\"", data_path.to_str().unwrap());

        let temp_path = Path::new(env!("CARGO_TARGET_TMPDIR"));
        debug!("Temp directory: \"{}\"", temp_path.to_str().unwrap());

        let work_path = temp_path.join(format!("fapi-{}", &RANDOM_UUID_PREFIX));
        debug!("Work directory: \"{}\"", work_path.to_str().unwrap());

        let conf_file = work_path.join("config.json");
        debug!("FAPI conf file: \"{}\"", conf_file.to_str().unwrap());

        if fs::metadata(&conf_file).map_or(false, |file_info| file_info.is_file()) {
            debug!("Re-using the existing FAPI configuration!");
        } else {
            Self::write_fapi_config(&conf_file, &data_path, &work_path, prof_name, tcti_conf);
        }

        env::set_var("TSS2_FAPICONF", conf_file.to_str().unwrap());

        Self {
            uniq_lock,
            prof_name,
            data_path,
            work_path,
            finalizer,
        }
    }

    fn write_fapi_config(conf_file: &Path, data_path: &Path, work_path: &Path, prof_name: &str, tcti_conf: &str) {
        if Path::try_exists(work_path).unwrap_or(true) {
            fs::remove_dir_all(work_path).expect("Failed to remove existing directory!");
        }

        fs::create_dir_all(work_path).expect("Failed to create subdirectories!");

        let prof_path = work_path.join("profiles");
        debug!("Prof directory: \"{}\"", prof_path.to_str().unwrap());
        fs::create_dir_all(&prof_path).expect("Failed to create subdirectories!");

        let keys_path = work_path.join("keystore");
        debug!("Keys directory: \"{}\"", keys_path.to_str().unwrap());
        fs::create_dir_all(&keys_path).expect("Failed to create subdirectories!");

        let user_path = keys_path.join("user");
        debug!("User key-store: \"{}\"", user_path.to_str().unwrap());
        fs::create_dir_all(user_path.join("policy")).expect("Failed to create subdirectories!");

        let syst_path = keys_path.join("system");
        debug!("Syst key-store: \"{}\"", syst_path.to_str().unwrap());
        fs::create_dir_all(syst_path.join("policy")).expect("Failed to create subdirectories!");

        let logs_path = work_path.join("eventlog");
        debug!("Logs directory: \"{}\"", logs_path.to_str().unwrap());
        fs::create_dir_all(&logs_path).expect("Failed to create subdirectories!");

        let mut content = fs::read_to_string(data_path.join("fapi-config.json.template")).expect("Failed to read input file!");
        content = content.replace("{{TCTI_CFG}}", tcti_conf);
        content = content.replace("{{PROF_CFG}}", prof_name);
        content = content.replace("{{PROF_DIR}}", prof_path.to_str().unwrap());
        content = content.replace("{{USER_DIR}}", user_path.to_str().unwrap());
        content = content.replace("{{SYST_DIR}}", syst_path.to_str().unwrap());
        content = content.replace("{{LOGS_DIR}}", logs_path.to_str().unwrap());

        trace!("FAPI conf data: {}", content.trim());
        fs::write(conf_file, &content).expect("Failed to write configuration to output file!");

        for entry in fs::read_dir(data_path.join("profiles")).unwrap().flatten() {
            let fname = entry.file_name();
            if fname.to_str().map_or(false, |str| str.starts_with("P_")) {
                let (path_src, path_dst) = (entry.path(), prof_path.join(fname));
                debug!("Copy: {:?} -> {:?}", path_src, path_dst);
                fs::copy(path_src, path_dst).expect("Failed to copy file!");
            }
        }
    }

    fn check_tpm_connection(host: &str, port: u16) {
        debug!("Connecting to SWTPM, please wait... [{}:{}]", host, port);
        let start_time = Instant::now();
        loop {
            match TcpStream::connect_timeout(&SocketAddr::new(IpAddr::from_str(host).unwrap(), port), Duration::from_secs(10)) {
                Ok(conn) => {
                    return conn.shutdown(std::net::Shutdown::Both).unwrap();
                }
                Err(_) => {
                    if start_time.elapsed().as_secs() > 100_u64 {
                        panic!("Failed to connect to the SWTPM. Is the SWTPM running?");
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn prof_name(&self) -> &str {
        self.prof_name
    }

    #[allow(dead_code)]
    pub fn data_path(&self) -> &Path {
        &self.data_path
    }

    #[allow(dead_code)]
    pub fn work_path(&self) -> &Path {
        &self.work_path
    }
}

impl Drop for TestConfiguration<'_> {
    fn drop(&mut self) {
        if let Some(finalizer) = self.finalizer.take() {
            finalizer();
        }
        *self.uniq_lock = false;
    }
}
