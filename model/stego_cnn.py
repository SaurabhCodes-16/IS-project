# model/stego_cnn.py

import torch
import torch.nn as nn

class SimpleStegoCNN(nn.Module):
    """
    A small CNN for binary steganalysis (stego / clean).
    Input: grayscale 64x64 images
    Output: logits for 2 classes (clean vs stego)
    """
    def __init__(self):
        super().__init__()
        self.features = nn.Sequential(
            nn.Conv2d(1, 16, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),

            nn.Conv2d(16, 32, 3, padding=1),
            nn.ReLU(),
            nn.MaxPool2d(2),

            nn.Conv2d(32, 64, 3, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool2d((4, 4)),
        )

        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(64 * 4 * 4, 128),
            nn.ReLU(),
            nn.Dropout(0.4),
            nn.Linear(128, 2)  # 2 classes: clean/stego
        )

    def forward(self, x):
        x = self.features(x)
        x = self.classifier(x)
        return x
