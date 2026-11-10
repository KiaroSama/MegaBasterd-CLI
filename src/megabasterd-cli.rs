fn main() {
    megabasterd_cli::terminal::panic_report::install();
    std::process::exit(megabasterd_cli::cli::run(std::env::args_os()));
}
