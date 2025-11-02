# utils/stego_scan.py

import cv2
import numpy as np
import torch
from pathlib import Path
import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from model.stego_cnn import SimpleStegoCNN

MODEL_PATH = Path(__file__).resolve().parents[1] / 'model' / 'stego_cnn.pth'


class StegoScanner:
    def __init__(self, model_path=None, device=None, threshold=0.5):
        self.device = device or (torch.device('cuda') if torch.cuda.is_available() else torch.device('cpu'))
        self.model = SimpleStegoCNN().to(self.device)

        if model_path is None:
            model_path = MODEL_PATH
        try:
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        except Exception:
            print('Warning: failed to load model weights. '
                  'The scanner will operate with random weights (for demo only).')

        self.model.eval()
        self.threshold = threshold

    def _preprocess(self, img_path):
        """
        Load image, convert to grayscale, resize to 64x64, normalize, convert to tensor.
        Returns: 1x1x64x64 torch tensor
        """
        img = cv2.imread(str(img_path), cv2.IMREAD_COLOR)
        if img is None:
            raise ValueError(f'Cannot read image: {img_path}')

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        resized = cv2.resize(gray, (64, 64)).astype('float32') / 255.0
        tensor = torch.from_numpy(resized).unsqueeze(0).unsqueeze(0)  # 1x1x64x64
        return tensor

    def is_image(self, filepath):
        ext = str(filepath).lower()
        return ext.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff'))

    def predict(self, filepath):
        """
        Return (is_stego: boolean, score: probability of stego)
        score > threshold => stego detected
        """
        if not self.is_image(filepath):
            return False, 0.0

        tensor = self._preprocess(filepath).to(self.device)
        with torch.no_grad():
            logits = self.model(tensor)
            probs = torch.softmax(logits, dim=1)[0, 1].item()
        return (probs > self.threshold), probs


# quick usage:
# scanner = StegoScanner()
# is_stego, score = scanner.predict('some.png')
