#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tundra_node::run().await
}
