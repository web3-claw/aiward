use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = ward::cli::Cli::parse();
    match ward::cli::dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(child_exit) = error.downcast_ref::<ward::cli::ChildExit>() {
                return ExitCode::from(child_exit.exit_code());
            }
            eprintln!("{error:?}");
            ExitCode::FAILURE
        }
    }
}
