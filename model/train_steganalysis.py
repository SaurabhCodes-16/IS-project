# model/train_steganalysis.py

import torch
from torch.utils.data import DataLoader, Dataset
import torch.nn as nn
import torch.optim as optim
import numpy as np
from stego_cnn import SimpleStegoCNN  # make sure this exists

# -------------------------------
# Dummy Dataset for testing
# -------------------------------
class DummyDataset(Dataset):
    def __init__(self, n=1000):
        # Random images 64x64 grayscale, normalized
        self.x = (np.random.rand(n, 1, 64, 64).astype('float32')) / 255.0
        # Random labels 0 or 1
        self.y = (np.random.rand(n) > 0.5).astype('int64')

    def __len__(self):
        return len(self.y)

    def __getitem__(self, idx):
        return torch.tensor(self.x[idx]), torch.tensor(self.y[idx])

# -------------------------------
# Training function
# -------------------------------
def train():
    # Initialize model
    model = SimpleStegoCNN()
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    model.to(device)

    # Dataset & dataloader
    ds = DummyDataset(2000)
    dl = DataLoader(ds, batch_size=32, shuffle=True)

    # Loss & optimizer
    criterion = nn.CrossEntropyLoss()
    opt = optim.Adam(model.parameters(), lr=1e-3)

    # Training loop
    for epoch in range(5):
        model.train()
        total, acc = 0, 0
        for xb, yb in dl:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            loss = criterion(logits, yb)
            opt.zero_grad()
            loss.backward()
            opt.step()

            preds = logits.argmax(dim=1)
            total += len(yb)
            acc += (preds == yb).sum().item()

        print(f"Epoch {epoch} acc={acc/total:.4f}")

    # Save trained model
    torch.save(model.state_dict(), 'stego_cnn.pth')
    print("Model saved as stego_cnn.pth")

# -------------------------------
# Run training
# -------------------------------
if __name__ == '__main__':
    train()
