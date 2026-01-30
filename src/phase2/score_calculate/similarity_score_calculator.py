from typing import Dict, List
import numpy as np
import torch
from transformers import AutoTokenizer, AutoModel
from tqdm import tqdm


class SimilarityCalculator:
    def __init__(self, model_name: str = "") -> None:
        self.model_name = model_name
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name)
        self.device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device).eval()
        self.index: np.ndarray | None = None
        self.index_mean: np.ndarray | None = None
        self.index_texts: list[str] = []

    def load_index(self, index_path: str) -> None:
        self.index = np.load(index_path)
        self.index_mean = self.index.mean(axis=0, keepdims=True)
        self.index_texts = []

    def load_index_with_mean(self, index_path: str, mean_path: str) -> None:
        """Load pre-saved centered index and its mean file."""
        self.index = np.load(index_path)
        self.index_mean = np.load(mean_path)
        self.index_texts = []

    def _embed_texts(self, texts: List[str], max_length: int = 512, batch_size: int = 16) -> np.ndarray:
        vecs: List[np.ndarray] = []
        with torch.no_grad():
            for i in range(0, len(texts), batch_size):
                batch = texts[i : i + batch_size]
                inputs = self.tokenizer(
                    batch,
                    return_tensors="pt",
                    truncation=True,
                    padding=True,
                    max_length=max_length,
                )
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
                outputs = self.model(**inputs)
                emb = outputs.last_hidden_state.mean(dim=1).cpu().numpy()
                vecs.append(emb)
        return np.vstack(vecs)

    @staticmethod
    def _make_windows(function_code: str, window_size: int = 5) -> Dict[int, str]:
        lines = [line.rstrip() for line in function_code.strip().split("\n")]
        blocks: Dict[int, str] = {}
        if len(lines) < window_size:
            chunk = [ln for ln in lines if ln.strip()]
            if chunk:
                blocks[0] = "\n".join(chunk)
            return blocks
        half = window_size // 2
        start_i = half
        end_i = len(lines) - half
        for i in range(start_i, end_i):
            start = i - half
            end = i + half + 1
            chunk = [ln for ln in lines[start:end] if ln.strip()]
            if chunk:
                blocks[i + 1] = "\n".join(chunk)
        return blocks
    
    def score_by_lines(self, function_code: str, window_size: int = 5) -> Dict[int, float]:
        if self.index is None:
            raise ValueError("Please call load_index first to load .npy vector database")

        blocks = self._make_windows(function_code, window_size)
        texts = list(blocks.values())
        if not texts:
            return {}

        emb = self._embed_texts(texts)
        if self.index_mean is not None:
            emb = emb - self.index_mean
            idx = self.index - self.index_mean
        else:
            idx = self.index
        emb_norm = emb / (np.linalg.norm(emb, axis=1, keepdims=True) + 1e-12)
        idx_norm = idx / (np.linalg.norm(idx, axis=1, keepdims=True) + 1e-12)

        sims = emb_norm @ idx_norm.T
        max_sims = sims.max(axis=1)

        line_scores: Dict[int, float] = {}
        for (line_no, _), s in zip(blocks.items(), max_sims.tolist()):
            line_scores[line_no] = float(s)
        return line_scores

if __name__ == "__main__":
    import os, json

    index_path = ""
    mean_path = ""
    test_path = ""

    if not os.path.exists(index_path):
        raise SystemExit(f"Index does not exist: {index_path}")
    if not os.path.exists(mean_path):
        raise SystemExit(f"Index mean does not exist: {mean_path}")
    if not os.path.exists(test_path):
        raise SystemExit(f"Test set does not exist: {test_path}")

    sc = SimilarityCalculator("")
    sc.load_index_with_mean(index_path, mean_path)

    def run_for_window(win: int, out_path: str) -> int:
        total_candidates = 0
        with open(test_path, "r", encoding="utf-8") as fin:
            for line in fin:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                code = obj.get("func") or ""
                if isinstance(code, str) and code.strip():
                    total_candidates += 1

        processed = 0
        with open(test_path, "r", encoding="utf-8") as fin, open(out_path, "w", encoding="utf-8") as fout:
            pbar = tqdm(total=total_candidates, desc=f"Eval w={win}", unit="sample")
            for idx, line in enumerate(fin):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                code = obj.get("func") or ""
                if not isinstance(code, str) or not code.strip():
                    continue
                scores = sc.score_by_lines(code, window_size=win)
                record = {
                    "idx": obj.get("idx"),
                    "target": obj.get("target"),
                    "line_scores": scores,
                }
                fout.write(json.dumps(record, ensure_ascii=False) + "\n")
                processed += 1
                pbar.update(1)
            pbar.close()
        return processed

    for w in [ 3, 5, 7]:
        out_w = f"embed_similarity_score/primevul_similarity_w{w}.jsonl"
        n = run_for_window(w, out_w)

