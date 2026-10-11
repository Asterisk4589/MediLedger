const { ethers } = require("hardhat");
async function main() {
  const c = await ethers.deployContract("MediLedger");
  await c.waitForDeployment();
  console.log("CONTRACT_ADDRESS=" + await c.getAddress());
}
main().catch(e => { console.error(e); process.exit(1); });
