use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = envgate::cli::Cli::parse();
    match envgate::cli::dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(child_exit) = error.downcast_ref::<envgate::cli::ChildExit>() {
                return ExitCode::from(child_exit.exit_code());
            }
            eprintln!("{error:?}");
            ExitCode::FAILURE
        }
    }
}
