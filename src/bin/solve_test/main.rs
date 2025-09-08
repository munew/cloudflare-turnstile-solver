use cf::solver::TurnstileSolver;
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() {
    let solver = Arc::new(TurnstileSolver::new().await);

    let t = Instant::now();
    let mut task = solver
        .create_task(
            "0x4AAAAAABdbdHypG5Crbw0P",
            "https://mune.sh/",
            None,
            None,
        )
        .await.unwrap();

    let result = task.solve().await;

    if let Ok(result) = result {
        println!("{:?}", result);
    } else {
        println!("err: {}", result.as_ref().unwrap_err().root_cause());
    }
    
    println!("Took {:?}", t.elapsed());
}
