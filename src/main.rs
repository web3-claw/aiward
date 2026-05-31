use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = aiward::cli::Cli::parse();
    match aiward::cli::dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(child_exit) = error.downcast_ref::<aiward::cli::ChildExit>() {
                return ExitCode::from(child_exit.exit_code());
            }
            eprintln!("{error:?}");
            ExitCode::FAILURE
        }
    }
}
