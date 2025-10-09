use clap::Parser;
use debugging_cli::cli::{Cli, Command, SnarkSubcommand};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    FmtSubscriber::builder().with_env_filter(filter).init();

    let cli = Cli::parse();


    
    match cli.command {
        Command::Snark(snark_args) => match snark_args.subcommand {
            SnarkSubcommand::MergeFris(args) => {
                args.run()?;
            }
            SnarkSubcommand::GenerateFinalProof(args) => {
                args.run()?;
            }
            SnarkSubcommand::SnarkWrap(args) => {
                args.run()?;
            }
        },
    }

    Ok(())
}

// use clap::{Args, Parser, Subcommand, ValueEnum};

// #[derive(Parser)]
// #[command(author, version, about, long_about = None)]
// struct Cli {
//     #[command(subcommand)]
//     command: Commands,
// }

// #[derive(Subcommand)]
// enum Commands {
//     // /// FRI proving commands
//     // Fri(FriArgs),
//     /// SNARK troubleshooting commands
//     Snark(SnarkArgs),
// }

// // #[derive(Args)]
// // struct FriArgs {
// //     #[command(subcommand)]
// //     command: FriCommands,
// // }

// // #[derive(Subcommand)]
// // enum FriCommands {
// //     /// Generates a FRI proof for a given circuit.
// //     Prove,
// // }

// #[derive(Args)]
// struct SnarkArgs {
//     #[command(subcommand)]
//     command: SnarkCommands,
// }

// #[derive(Subcommand)]
// enum SnarkCommands {
//     // /// Generates a SNARK proof, optionally stopping at a specific stage.
//     // Prove(SnarkProveArgs),
//     /// Merges FRI proofs.
//     MergeFris(MergeFrisArgs),
//     // /// Finalizes the SNARK proof.
//     // Finalization,
//     // /// Generates the wrapper proof.
//     // Wrapper,
// }

// #[derive(Args)]
// #[group(required = true, multiple = false)]
// struct Source {
//     /// Load data from the sequencer.
//     #[arg(long)]
//     sequencer: Option<String>,
//     /// Load data from local files.
//     #[arg(long)]
//     local_file: Option<String>,
// }

// #[derive(Args)]
// struct SnarkProveArgs {
//     /// Stop the proving process at a specific stage.
//     #[arg(long)]
//     until: Option<SnarkProveUntil>,
//     #[command(flatten)]
//     from: Source,
// }

// #[derive(Args)]
// struct MergeFrisArgs {
//     #[command(flatten)]
//     from: Source,
//     // #[command(flatten)]
//     // to: String,
// }

// #[derive(Clone, ValueEnum)]
// enum SnarkProveUntil {
//     /// Stop after the aggregation phase.
//     Aggregation,
//     /// Stop after the scheduler phase.
//     Scheduler,
//     /// Stop after the final proof generation.
//     Final,
// }

// fn main() {
//     let cli = Cli::parse();

//     match &cli.command {
//         // Commands::Fri(fri_args) => match fri_args.command {
//         //     FriCommands::Prove => {
//         //         todo!("Implement FRI proving logic here");
//         //     }
//         // },
//         Commands::Snark(snark_args) => match &snark_args.command {
//             // SnarkCommands::Prove(args) => {
//             //     if let Some(until) = &args.until {
//             //         match until {
//             //             SnarkProveUntil::Aggregation => {
//             //                 println!("Running SNARK prove until aggregation...");
//             //             }
//             //             SnarkProveUntil::Scheduler => {
//             //                 println!("Running SNARK prove until scheduler...");
//             //             }
//             //             SnarkProveUntil::Final => todo!(),
//             //         }
//             //         // Add your SNARK prove logic here
//             //     }
//             // }
//             SnarkCommands::MergeFris(_args) => {
//                 println!("Running SNARK merge_fris...");
//                 // Add your merge FRIs logic here
//             } // SnarkCommands::Finalization => {}
//               // SnarkCommands::MergeFris(args) => {
//               //     println!("Running SNARK merge_fris...");
//               //     // Add your merge FRIs logic here
//               // }
//               // SnarkCommands::Finalization => {
//               //     println!("Running SNARK finalization...");
//               //     // Add your finalization logic here
//               // }
//               // SnarkCommands::Wrapper => {
//               //     println!("Running SNARK wrapper...");
//               //     // Add your wrapper logic here
//               // }
//         },
//     }
// }
