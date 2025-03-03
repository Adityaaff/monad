const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require('crypto');
const { ethers } = require("ethers");
const app = express();
const path = require('path');



const ENCRYPTION_KEY = "a2f42f8659827d1d617de10cbac7bfe751e487f23a6701090dc957206cabaad0";  // Use a secure key here

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'test')));

const RPC_URL = "https://testnet-rpc.monad.xyz";
const EXPLORER_URL = "https://testnet.monadexplorer.com/tx";
const POLL_INTERVAL_MS = 500;

// Cache for storing contract types (price cache no longer needed)
const typeCache = new Map();

const provider = new ethers.JsonRpcProvider(RPC_URL);
const IV_LENGTH = 16;

// Encryption helper function for cookies
    function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
    }

// Decryption helper function for cookies
    function decrypt(text) {
    const textParts = text.split(':');
    const iv = Buffer.from(textParts[0], 'hex');
    const encryptedText = textParts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    console.log(decrypted)
    return decrypted;
    }

// Generate wallet
    function generateWallet() {
    const wallet = ethers.Wallet.createRandom();
    const mnemonic = wallet.mnemonic.phrase;
    const privateKey = wallet.privateKey;
    const address = wallet.address;
    console.log(mnemonic, privateKey, address)
    return { wallet, mnemonic, privateKey, address };
    }


    async function verifyContract(contractAddress) {
        const code = await provider.getCode(contractAddress);
        if (code === "0x") return false;
        console.log("Contract verified at:", contractAddress);
        return true;
    }
  
  function extractContractAddress(link) {
    try {
      const url = new URL(link);
      const pathParts = url.pathname.split("/");
      const contractIndex = pathParts.indexOf("mint-terminal") + 2;
      if (contractIndex < pathParts.length && ethers.isAddress(pathParts[contractIndex])) {
        return pathParts[contractIndex].toLowerCase();
      }
      return null;
    } catch (error) {
      console.error("Invalid URL provided:", error.message);
      return null;
    }
  }
  
  async function detectContractType(contractAddress, wallet) {
    if (typeCache.has(contractAddress)) {
      return typeCache.get(contractAddress);
    }
  
    try {
      const contract = new ethers.Contract(
        contractAddress,
        ["function supportsInterface(bytes4 interfaceId) view returns (bool)"],
        provider
      );
  
      const isERC721 = await contract.supportsInterface("0x80ac58cd");
      const addressPadded = wallet.address.slice(2).toLowerCase().padStart(64, "0");
  
      if (isERC721) {
        console.log("Detected contract type: ERC721");
        const batchMintData = `0x1564c7e0${addressPadded}0000000000000000000000000000000000000000000000000000000000000001`;
        let supportsBatchMint = false;
        try {
          await provider.estimateGas({
            to: contractAddress,
            value: 0n,
            data: batchMintData,
            from: wallet.address,
          });
          supportsBatchMint = true;
          console.log("ERC721 supports batch minting");
        } catch (error) {
          console.log("ERC721 does not support batch minting (0x1564c7e0):", error.message);
        }
        const typeInfo = { type: "ERC721", supportsBatchMint };
        typeCache.set(contractAddress, typeInfo);
        return typeInfo;
      }
  
      const isERC1155 = await contract.supportsInterface("0xd9b67a26");
      if (isERC1155) {
        console.log("Detected contract type: ERC1155");
        typeCache.set(contractAddress, { type: "ERC1155", supportsBatchMint: true });
        return { type: "ERC1155", supportsBatchMint: true };
      }
  
      throw new Error("Could not determine contract type");
    } catch (error) {
      console.error("Failed to detect contract type:", error.message);
      return null;
    }
  }
  
  async function detectValidTokenId(contractAddress, mintPriceWei, tokenStandard, quantity = 1, supportsBatchMint, wallet) {
    const addressPadded = wallet.address.slice(2).toLowerCase().padStart(64, "0");
    let validId = null;
  
    for (let id = 0; id <= 5; id++) {
      const tokenIdPadded = BigInt(id).toString(16).padStart(64, "0");
      let rawData;
  
      if (tokenStandard === "ERC721") {
        if (supportsBatchMint) {
          const quantityPadded = BigInt(quantity).toString(16).padStart(64, "0");
          rawData = `0x1564c7e0${addressPadded}${quantityPadded}`;
        } else {
          rawData = `0x9f93f779${addressPadded}${tokenIdPadded}`;
        }
      } else {
        const quantityPadded = BigInt(quantity).toString(16).padStart(64, "0");
        const bytesOffset = "0000000000000000000000000000000000000000000000000000000000000080";
        const bytesData = "0000000000000000000000000000000000000000000000000000000000000000";
        rawData = `0x9b4f3af5${addressPadded}${tokenIdPadded}${quantityPadded}${bytesOffset}${bytesData}`;
      }
  
      const txParams = {
        to: contractAddress,
        value: mintPriceWei,
        data: rawData,
        from: wallet.address,
      };
  
      try {
        await provider.estimateGas(txParams);
        validId = id;
        console.log(`Found valid Token ID: ${id}`);
        break;
      } catch (error) {
        console.log(`Token ID ${id} failed gas estimation:`, error.message);
      }
    }
  
    return validId !== null ? validId.toString() : null;
  }
  
  async function isMintActive(contractAddress, tokenStandard, tokenId, quantity = 1, mintPriceWei, supportsBatchMint, wallet) {
    const addressPadded = wallet.address.slice(2).toLowerCase().padStart(64, "0");
    const tokenIdPadded = BigInt(tokenId).toString(16).padStart(64, "0");
  
    let rawData;
    if (tokenStandard === "ERC721") {
      if (supportsBatchMint) {
        const quantityPadded = BigInt(quantity).toString(16).padStart(64, "0");
        rawData = `0x1564c7e0${addressPadded}${quantityPadded}`;
      } else {
        rawData = `0x9f93f779${addressPadded}${tokenIdPadded}`;
      }
    } else {
      const quantityPadded = BigInt(quantity).toString(16).padStart(64, "0");
      const bytesOffset = "0000000000000000000000000000000000000000000000000000000000000080";
      const bytesData = "0000000000000000000000000000000000000000000000000000000000000000";
      rawData = `0x9b4f3af5${addressPadded}${tokenIdPadded}${quantityPadded}${bytesOffset}${bytesData}`;
    }
  
    const valuesToTest = [0n, mintPriceWei];
    for (const value of valuesToTest) {
      const txParams = {
        to: contractAddress,
        value: value,
        data: rawData,
        from: wallet.address,
      };
  
      try {
        await provider.estimateGas(txParams);
        console.log(`Minting is active with value: ${ethers.formatEther(value)} MON`);
        return true;
      } catch (error) {
        console.log(`Minting check failed with value ${ethers.formatEther(value)} MON:, error.message`);
        if (error.data) console.log("Error data:", error.data);
      }
    }
  
    console.log("Minting not yet active for any tested value.");
    return false;
  }
  
  async function waitForMintStart(contractAddress, tokenStandard, tokenId, quantity, mintPriceWei, supportsBatchMint, wallet) {
    console.log("Checking if minting has started...");
    while (!(await isMintActive(contractAddress, tokenStandard, tokenId, quantity, mintPriceWei, supportsBatchMint, wallet))) {
      //console.log(Minting not started. Waiting ${POLL_INTERVAL_MS}ms...);
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
    console.log("Minting has started! Proceeding with mint...");
  }
  
  async function mintNFT(contractAddress, mintPrice, tokenId, quantity = 1, tokenStandard, supportsBatchMint, privateKey) {
    try {
      const wallet = new ethers.Wallet(privateKey, provider);
      if (!(await verifyContract(contractAddress))) throw new Error("Contract verification failed");
  
      const walletBalance = await provider.getBalance(wallet.address);
      const mintPriceWei = ethers.parseEther(mintPrice.toString());
      const totalCost = mintPriceWei * BigInt(quantity);
  
      if (mintPriceWei > 0n && walletBalance < totalCost) {
        throw new Error(`Insufficient balance: ${ethers.formatEther(walletBalance)} MON < ${ethers.formatEther(totalCost)} MON required`);
      }
  
      await waitForMintStart(contractAddress, tokenStandard, tokenId, quantity, mintPriceWei, supportsBatchMint, wallet);
  
      //console.log(Minting to ${wallet.address}, Token ID: ${tokenStandard === "ERC721" && supportsBatchMint ? "auto-incremented" : tokenId}, Quantity: ${quantity});
      //console.log(Sending value: ${ethers.formatEther(totalCost)} MON);
  
      let rawData;
      const addressPadded = wallet.address.slice(2).toLowerCase().padStart(64, "0");
      const tokenIdPadded = BigInt(tokenId).toString(16).padStart(64, "0");
  
      if (tokenStandard === "ERC721") {
        if (supportsBatchMint) {
          const quantityPadded = BigInt(quantity).toString(16).padStart(64, "0");
          rawData = `0x1564c7e0${addressPadded}${quantityPadded}`;
          //console.log(ERC721 batch mint calldata: ${rawData});
        } else {
          rawData = `0x9f93f779${addressPadded}${tokenIdPadded}`;
          console.log(`ERC721 single mint calldata: ${rawData}`);
        }
      } else {
        const quantityPadded = BigInt(quantity).toString(16).padStart(64, "0");
        const bytesOffset = "0000000000000000000000000000000000000000000000000000000000000080";
        const bytesData = "0000000000000000000000000000000000000000000000000000000000000000";
        rawData = `0x9b4f3af5${addressPadded}${tokenIdPadded}${quantityPadded}${bytesOffset}${bytesData}`;
        console.log(`ERC1155 calldata: ${rawData}`);
      }
  
      const txParams = {
        to: contractAddress,
        value: totalCost,
        data: rawData,
        from: wallet.address,
      };
  
      let gasEstimate;
      try {
        gasEstimate = await provider.estimateGas(txParams);
       // console.log(Estimated Gas: ${gasEstimate.toString()});
      } catch (error) {
        console.error("Gas estimation failed:", error.message);
        console.error("Error data:", error.data || "No data");
        gasEstimate = BigInt("250000");
      //  console.log(Using fallback gas limit: ${gasEstimate});
      }
  
      const txConfig = {
        ...txParams,
        gasLimit: gasEstimate * BigInt(120) / BigInt(100),
        maxFeePerGas: ethers.parseUnits("52", "gwei"),
        maxPriorityFeePerGas: ethers.parseUnits("52", "gwei"),
      };
  
      console.log("Full transaction config:", txConfig);
  
      const tx = await wallet.sendTransaction(txConfig);
      console.log("Transaction sent:", tx.hash);
  
      const receipt = await tx.wait();
      if (receipt.status === 1) {
        console.log(`${tokenStandard} NFT minted successfully!`);
        return { success: true, txHash: tx.hash };
      } else {
        throw new Error("Transaction failed: " + JSON.stringify(receipt));
      }
    } catch (error) {
      console.error("Error minting NFT:", error.message);
      if (error.data) console.error("Raw error data:", error.data);
      return { success: false, error: error.message };
    }
  }
// Generate and store wallet in cookies
app.post("/generate-wallet", (req, res) => {
  const { wallet, mnemonic, privateKey, address } = generateWallet();
  const encryptedMnemonic = encrypt(mnemonic);
  const encryptedPrivateKey = encrypt(privateKey);

  res.cookie("encryptedMnemonic", encryptedMnemonic, { httpOnly: true, secure: true });
  res.cookie("encryptedPrivateKey", encryptedPrivateKey, { httpOnly: true, secure: true });

  res.json({
    address,
    mnemonic,
    privateKey,
    message: "Wallet generated and stored in secure cookies. Please save them securely."
  });
});
app.post("/mint", async (req, res) => {
  const encryptedPrivateKey = req.cookies.encryptedPrivateKey;
    const privateKey = decrypt(encryptedPrivateKey);
    console.log("Decrypted Private Key:", privateKey);  
    const { link, quantity, mintPrice } = req.body;
  if (!link) return res.status(400).json({ error: "No link provided" });
  if (!mintPrice || isNaN(parseFloat(mintPrice))) return res.status(400).json({ error: "Please enter a valid mint price (e.g., 0.01 or 0 for free)" });

  const contractAddress = extractContractAddress(link);
  if (!contractAddress) return res.status(400).json({ error: "Invalid contract address" });

  try {
    const wallet = new ethers.Wallet(privateKey, provider);
    const typeInfo = await detectContractType(contractAddress, wallet);
    console.log(wallet, contractAddress)
    if (!typeInfo) throw new Error("Could not detect contract type");

    const tokenId = await detectValidTokenId(contractAddress, ethers.parseEther(mintPrice), typeInfo.type, quantity || 1, typeInfo.supportsBatchMint, wallet);
    if (!tokenId) throw new Error("Could not detect valid token ID");

    const result = await mintNFT(contractAddress, mintPrice, tokenId, quantity || 1, typeInfo.type, typeInfo.supportsBatchMint, privateKey);
    
    if (result.success) {
      res.json({ success: true, txHash: result.txHash, explorerLink:`${EXPLORER_URL}/${result.txHash}` });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});