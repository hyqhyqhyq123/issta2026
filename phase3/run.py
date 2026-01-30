# coding=utf-8
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

from __future__ import absolute_import
import os
import torch
import json
import random
import logging
import argparse
import numpy as np
from model import UniXcoderForVulDetection
from tqdm import tqdm
from torch.utils.data import DataLoader, SequentialSampler, RandomSampler, TensorDataset
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
from transformers import RobertaTokenizer, get_linear_schedule_with_warmup
from torch.optim import AdamW 

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(name)s -   %(message)s',
                    datefmt='%m/%d/%Y %H:%M:%S',
                    level=logging.INFO)
logger = logging.getLogger(__name__)


class Example(object):
    """A training/test sample"""

    def __init__(self, idx, code, label):
        self.idx = idx
        self.code = code
        self.label = label


def read_examples(filename, dataset_type="devign"):
    """Read samples from JSONL file"""
    examples = []
    with open(filename, encoding="utf-8") as f:
        for idx, line in enumerate(f):
            line = line.strip()
            if not line:
                continue

            try:
                js = json.loads(line)
            except json.JSONDecodeError as e:
                logger.warning(f"JSON parsing error, skipping line {idx}: {e}")
                continue

            label = js['target']
            code = js.get('func', '')
            

            if isinstance(label, str):
                try:
                    label = int(label)
                except ValueError:
                    if label.lower() in ['true', 'false']:
                        label = 1 if label.lower() == 'true' else 0
                    else:
                        logger.warning(f"Label value cannot be converted to integer: {label}")
                        continue
            elif isinstance(label, bool):
                label = 1 if label else 0

            if label not in [0, 1]:
                logger.warning(f"Label value is not 0 or 1: {label}, skipping this sample")
                continue

            if 'idx' not in js:
                js['idx'] = idx

            examples.append(
                Example(
                    idx=js['idx'],
                    code=code,
                    label=label,
                )
            )

    logger.info(f"Read {len(examples)} samples from {filename}")
    return examples


class InputFeatures(object):
    """Features of a training/test sample"""

    def __init__(self, example_id, source_ids, attention_mask, label):
        self.example_id = example_id
        self.source_ids = source_ids
        self.attention_mask = attention_mask
        self.label = label


def convert_examples_to_features(examples, tokenizer, args, stage=None):
    """
    Convert code samples to UniXcoder input format
    Format: [CLS] <encoder-only> [SEP] code [SEP]
    """
    features = []

    for example_index, example in enumerate(examples):
        code = example.code
        label = example.label

        tokens = tokenizer.tokenize(code)

        max_code_length = args.max_source_length - 5
        if len(tokens) > max_code_length:
            tokens = tokens[:max_code_length]

        source_tokens = [tokenizer.cls_token, "<encoder-only>", tokenizer.sep_token] + tokens + [tokenizer.sep_token]

        source_ids = tokenizer.convert_tokens_to_ids(source_tokens)

        padding_length = args.max_source_length - len(source_ids)
        source_ids += [tokenizer.pad_token_id] * padding_length

        attention_mask = [1] * len(source_tokens) + [0] * padding_length

        features.append(
            InputFeatures(
                example_id=example_index,
                source_ids=source_ids,
                attention_mask=attention_mask,
                label=label
            )
        )

    return features


def compute_metrics(predictions, labels, probabilities=None):
    """
    Calculate vulnerability detection evaluation metrics
    """
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.metrics import matthews_corrcoef, roc_auc_score, roc_curve
    import numpy as np
    
    accuracy = accuracy_score(labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average='binary', zero_division=0
    )
    
    from sklearn.metrics import fbeta_score
    f2_score = fbeta_score(labels, predictions, beta=2, average='binary', zero_division=0)
    
    mcc = matthews_corrcoef(labels, predictions)
    
    report = classification_report(
        labels, predictions,
        target_names=['Safe', 'Vulnerable'],
        output_dict=True,
        digits=4
    )
    
    cm = confusion_matrix(labels, predictions)
    
    tn, fp, fn, tp = cm.ravel()
    sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    gmean = np.sqrt(sensitivity * specificity) if sensitivity > 0 and specificity > 0 else 0
    
    false_negative_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    metrics = {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "f2_score": float(f2_score),
        "mcc": float(mcc),
        "gmean": float(gmean),
        "sensitivity": float(sensitivity),
        "specificity": float(specificity),
        "false_negative_rate": float(false_negative_rate),
        "false_positive_rate": float(false_positive_rate),
        "confusion_matrix": cm.tolist(),
        "detailed_report": report,
        "cm_details": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp)
        }
    }
    
    if probabilities is not None:
        try:
            vul_probs = [prob[1] for prob in probabilities]
            auc = roc_auc_score(labels, vul_probs)
            metrics["auc"] = float(auc)
            
            fpr, tpr, thresholds = roc_curve(labels, vul_probs)
            tpr_target = 0.95
            idx = np.where(tpr >= tpr_target)[0]
            if len(idx) > 0:
                fpr_at_95tpr = fpr[idx[0]]
                metrics["fpr_at_95tpr"] = float(fpr_at_95tpr)
            else:
                metrics["fpr_at_95tpr"] = 1.0
        except Exception as e:
            logger.warning(f"Error calculating AUC: {e}")
            metrics["auc"] = 0.0
            metrics["fpr_at_95tpr"] = 1.0
    
    return metrics


def set_seed(seed=42):
    """Set random seed"""
    random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def train(args, train_dataset, eval_dataset, model, tokenizer):
    """Train model"""
    train_sampler = RandomSampler(train_dataset)
    train_dataloader = DataLoader(
        train_dataset, sampler=train_sampler,
        batch_size=args.train_batch_size
    )
    
    train_labels = train_dataset.tensors[-1]
    class_counts = torch.bincount(train_labels)
    total = len(train_labels)
    class_weights = total / (len(class_counts) * class_counts.float())
    class_weights = class_weights.to(args.device)
    
    model.set_class_weights(class_weights)
    
    no_decay = ['bias', 'LayerNorm.weight']
    optimizer_grouped_parameters = [
        {
            'params': [p for n, p in model.named_parameters() if not any(nd in n for nd in no_decay)],
            'weight_decay': args.weight_decay
        },
        {
            'params': [p for n, p in model.named_parameters() if any(nd in n for nd in no_decay)],
            'weight_decay': 0.0
        }
    ]
    
    optimizer = AdamW(
        optimizer_grouped_parameters,
        lr=args.learning_rate,
        eps=args.adam_epsilon
    )
    
    total_steps = len(train_dataloader) * args.num_train_epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_steps * 0.1),
        num_training_steps=total_steps
    )
    
    global_step = 0
    save_metric = getattr(args, "save_metric", "f1")
    best_val = -1.0
    best_epoch = 0
    training_losses = []
    patience = args.patience if hasattr(args, 'patience') else 3
    no_improve_count = 0
    
    for epoch in range(int(args.num_train_epochs)):
        model.train()
        epoch_loss = 0.0
        
        progress_bar = tqdm(train_dataloader, desc=f"Training")
        for step, batch in enumerate(progress_bar):
            batch = tuple(t.to(args.device) for t in batch)
            source_ids, attention_mask, labels = batch
            
            outputs = model(source_ids, attention_mask=attention_mask, labels=labels)
            loss = outputs['loss'] if isinstance(outputs, dict) else outputs[0]
            
            if torch.isnan(loss):
                continue
            
            loss.backward()
            
            torch.nn.utils.clip_grad_norm_(model.parameters(), args.max_grad_norm)
            
            optimizer.step()
            scheduler.step()
            model.zero_grad()
            
            epoch_loss += loss.item()
            global_step += 1
            
            progress_bar.set_postfix({'loss': loss.item()})
            
            # 记录损失和预测分布（每100步）
            if global_step % 100 == 0:
                training_losses.append(loss.item())
                # 检查当前批次的预测分布
                with torch.no_grad():
                    logits = outputs['logits'] if isinstance(outputs, dict) else outputs[1]
                    preds = torch.argmax(logits, dim=-1)
                    pred_dist = torch.bincount(preds, minlength=2)
                    label_dist = torch.bincount(labels, minlength=2)
            pass
        
        avg_epoch_loss = epoch_loss / len(train_dataloader)
        
        if args.do_eval:
            eval_results = evaluate(args, model, eval_dataset, "Validation")
            
            # 根据 save_metric 选择当前指标值
            if save_metric == 'accuracy':
                current_val = eval_results['accuracy']
            elif save_metric == 'mcc':
                current_val = eval_results['mcc']
            else:  # f1
                current_val = eval_results['f1']
            
            # 保存最佳模型（基于选择的指标）
            if current_val > best_val:
                best_val = current_val
                best_epoch = epoch + 1
                no_improve_count = 0
                
                checkpoint_prefix = f'checkpoint-best-{save_metric}'
                output_dir = os.path.join(args.output_dir, checkpoint_prefix)
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                
                model_to_save = model.module if hasattr(model, 'module') else model
                model_path = os.path.join(output_dir, "pytorch_model.bin")
                torch.save(model_to_save.state_dict(), model_path)
                
                tokenizer.save_pretrained(output_dir)
                
                config = {
                    "model_name": args.model_name_or_path,
                    "num_labels": 2,
                    "f1": eval_results['f1'],
                    "accuracy": eval_results['accuracy'],
                    "precision": eval_results['precision'],
                    "recall": eval_results['recall'],
                    "mcc": eval_results['mcc'],
                    "epoch": epoch + 1,
                    "save_metric": save_metric,
                    "best_val": best_val,
                    "class_weights": class_weights.cpu().numpy().tolist(),
                    "args": {}
                }
                for key, value in vars(args).items():
                    if isinstance(value, torch.device):
                        config["args"][key] = str(value)
                    elif isinstance(value, (int, float, str, bool, list, dict, type(None))):
                        config["args"][key] = value
                    else:
                        config["args"][key] = str(value)
                config_path = os.path.join(output_dir, "config.json")
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                
                eval_metrics = {
                    "f1": eval_results['f1'],
                    "accuracy": eval_results['accuracy'],
                    "precision": eval_results['precision'],
                    "recall": eval_results['recall'],
                    "mcc": eval_results['mcc']
                }
                eval_path = os.path.join(output_dir, "eval_results.json")
                with open(eval_path, 'w') as f:
                    json.dump(eval_metrics, f, indent=2)
            else:
                no_improve_count += 1
                
                if no_improve_count >= patience:
                    break
    
    loss_dir = os.path.join(args.output_dir, 'training_logs')
    os.makedirs(loss_dir, exist_ok=True)
    loss_path = os.path.join(loss_dir, "training_losses.json")
    with open(loss_path, 'w') as f:
        json.dump(training_losses, f)
    
    return best_val


def evaluate(args, model, eval_dataset, prefix="Evaluation"):
    """Evaluate model"""
    eval_sampler = SequentialSampler(eval_dataset)
    eval_dataloader = DataLoader(
        eval_dataset, sampler=eval_sampler,
        batch_size=args.eval_batch_size
    )
    
    model.eval()
    all_predictions = []
    all_labels = []
    all_probabilities = []
    eval_loss = 0.0
    
    progress_bar = tqdm(eval_dataloader, desc=prefix)
    for batch in progress_bar:
        batch = tuple(t.to(args.device) for t in batch)
        source_ids, attention_mask, labels = batch
        
        with torch.no_grad():
            outputs = model(source_ids, attention_mask=attention_mask, labels=labels)
            
            if isinstance(outputs, dict):
                loss = outputs.get('loss')
                logits = outputs['logits']
            else:
                loss, logits = outputs[0], outputs[1]
                
            probabilities = torch.softmax(logits, dim=-1)
            
            if loss is not None:
                eval_loss += loss.item()
                
            predictions = torch.argmax(logits, dim=-1)
            all_predictions.extend(predictions.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())
            all_probabilities.extend(probabilities.cpu().numpy())
    
    metrics = compute_metrics(all_predictions, all_labels, all_probabilities)
    
    return metrics


def predict_single_code(args, model, tokenizer, code):
    """Predict single code"""
    tokens = tokenizer.tokenize(code)
    max_code_length = args.max_source_length - 5
    if len(tokens) > max_code_length:
        tokens = tokens[:max_code_length]
    
    source_tokens = [tokenizer.cls_token, "<encoder-only>", tokenizer.sep_token] + tokens + [tokenizer.sep_token]
    source_ids = tokenizer.convert_tokens_to_ids(source_tokens)
    
    padding_length = args.max_source_length - len(source_ids)
    source_ids += [tokenizer.pad_token_id] * padding_length
    attention_mask = [1] * len(source_tokens) + [0] * padding_length
    
    source_ids = torch.tensor([source_ids]).to(args.device)
    attention_mask = torch.tensor([attention_mask]).to(args.device)
    
    model.eval()
    with torch.no_grad():
        outputs = model(source_ids, attention_mask=attention_mask)
        logits = outputs['logits'] if isinstance(outputs, dict) else outputs[0]
        probabilities = torch.softmax(logits, dim=-1)
        predictions = torch.argmax(logits, dim=-1)
    
    vul_prob = probabilities[0][1].item()
    safe_prob = probabilities[0][0].item()
    result = "Vulnerable" if predictions.item() == 1 else "Safe"
    
    return {
        "result": result,
        "vulnerability_probability": vul_prob,
        "safety_probability": safe_prob,
        "prediction": predictions.item(),
        "confidence": max(vul_prob, safe_prob)
    }


def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--model_name_or_path", default="microsoft/unixcoder-base-nine", type=str,
                        help="Pretrained model path, recommend microsoft/unixcoder-base-nine (supports C/C++)")
    
    parser.add_argument("--train_data_file", default=None, type=str,
                        help="Training data file path (JSONL format)")
    parser.add_argument("--eval_data_file", default=None, type=str,
                        help="Validation data file path (JSONL format)")
    parser.add_argument("--test_data_file", default=None, type=str,
                        help="Test data file path (JSONL format)")
    
    parser.add_argument("--dataset_type", type=str, default="devign",
                        choices=['devign', 'primevul'],
                        help="Dataset type: devign, primevul")
    parser.add_argument("--dataset_name", type=str, default="",
                        help="Dataset name (for auto-building paths, ignored if --train_data_file etc. are specified)")
    
    parser.add_argument("--do_train", action='store_true', help="Train model")
    parser.add_argument("--do_eval", action='store_true', help="Evaluate on validation set")
    parser.add_argument("--do_test", action='store_true', help="Evaluate on test set")
    parser.add_argument("--do_predict", action='store_true', help="Predict single code")
    
    parser.add_argument("--max_source_length", default=512, type=int, help="Maximum input sequence length")
    parser.add_argument("--train_batch_size", default=16, type=int, help="Training batch size")
    parser.add_argument("--eval_batch_size", default=32, type=int, help="Evaluation batch size")
    parser.add_argument("--learning_rate", default=2e-5, type=float, help="Learning rate")
    parser.add_argument("--weight_decay", default=0.01, type=float, help="Weight decay")
    parser.add_argument("--adam_epsilon", default=1e-8, type=float)
    parser.add_argument("--max_grad_norm", default=1.0, type=float, help="Maximum gradient norm")
    parser.add_argument("--num_train_epochs", default=10, type=int, help="Number of training epochs")
    parser.add_argument("--patience", default=3, type=int, help="Early stopping patience")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--save_metric", type=str, default="f1",
                        choices=["f1", "accuracy", "mcc"],
                        help="Metric to save best model on validation set: f1, accuracy or mcc")
    
    parser.add_argument("--code", type=str, help="Code snippet to predict")
    parser.add_argument("--output_dir", default="saved_models/vul_detection", type=str)
    parser.add_argument("--load_model_path", type=str, help="Path to load trained model")

    args = parser.parse_args()
    
    # 设置设备
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    args.device = device
    logger.info(f"使用设备: {device}")
    
    # 设置随机种子
    set_seed(args.seed)
    
    # 创建输出目录
    os.makedirs(args.output_dir, exist_ok=True)
    
    if not args.dataset_name:
        args.dataset_name = args.dataset_type
    
    # 处理数据文件路径
    
    # 如果没有指定文件路径，则根据 dataset_type 和 dataset_name 自动构建
    if not args.train_data_file:
        data_dir = f"data/{args.dataset_name}"
        args.train_data_file = os.path.join(data_dir, "train_dataset.jsonl")
        args.eval_data_file = os.path.join(data_dir, "val_dataset.jsonl")
        args.test_data_file = os.path.join(data_dir, "test_dataset.jsonl")
        logger.info(f"自动构建数据路径（数据集: {args.dataset_name}）")
    
    logger.info(f"训练文件: {args.train_data_file}")
    logger.info(f"验证文件: {args.eval_data_file}")
    logger.info(f"测试文件: {args.test_data_file}")
    
    # 检查文件是否存在（仅在需要时检查）
    if args.do_train and not os.path.exists(args.train_data_file):
        logger.error(f"训练文件不存在: {args.train_data_file}")
        return
    if args.do_eval and not os.path.exists(args.eval_data_file):
        logger.error(f"验证文件不存在: {args.eval_data_file}")
        return
    if args.do_test and not os.path.exists(args.test_data_file):
        logger.error(f"测试文件不存在: {args.test_data_file}")
        return
    
    # 加载 tokenizer
    tokenizer = RobertaTokenizer.from_pretrained(args.model_name_or_path)
    # 添加 UniXcoder 的特殊标记
    special_tokens = ["<encoder-only>", "<decoder-only>", "<encoder-decoder>", "<mask0>"]
    tokenizer.add_tokens(special_tokens, special_tokens=True)
    
    # 预测单条代码
    if args.do_predict and args.code:
        logger.info("预测单条代码...")
        
        # 加载模型
        model = UniXcoderForVulDetection(args.model_name_or_path)
        
        # 加载训练好的模型权重
        if args.load_model_path:
            state_dict = torch.load(args.load_model_path, map_location='cpu')
            # 处理多GPU训练保存的模型
            if all(k.startswith('module.') for k in state_dict.keys()):
                state_dict = {k[7:]: v for k, v in state_dict.items()}
            model.load_state_dict(state_dict)
            logger.info(f"加载模型权重: {args.load_model_path}")
        
        model.to(args.device)
        
        # 预测
        result = predict_single_code(args, model, tokenizer, args.code)
        
        print("\n" + "=" * 50)
        print("漏洞检测结果")
        print("=" * 50)
        print(f"预测结果: {result['result']}")
        print(f"漏洞概率: {result['vulnerability_probability']:.4f}")
        print(f"安全概率: {result['safety_probability']:.4f}")
        print(f"置信度: {result['confidence']:.4f}")
        
        if result['result'] == "漏洞":
            print("警告: 检测到潜在漏洞")
            if result['vulnerability_probability'] > 0.7:
                print("⚠ 高风险漏洞 (概率 > 70%)")
            elif result['vulnerability_probability'] > 0.5:
                print("⚠ 中风险漏洞 (概率 > 50%)")
        else:
            print("安全: 未检测到漏洞")
        
        return
    
    # 加载模型
    model = UniXcoderForVulDetection(args.model_name_or_path)
    
    # 如果没有指定模型路径，但需要评估/测试，尝试自动加载最佳模型
    if not args.load_model_path and (args.do_eval or args.do_test) and not args.do_train:
        save_metric = getattr(args, "save_metric", "f1")
        checkpoint_dir = os.path.join(args.output_dir, f'checkpoint-best-{save_metric}')
        model_path = os.path.join(checkpoint_dir, "pytorch_model.bin")
        if os.path.exists(model_path):
            args.load_model_path = model_path
            logger.info(f"自动加载最佳模型: {model_path}")
        else:
            logger.warning(f"未找到最佳模型: {model_path}，将使用未训练的模型")
    
    # 加载已训练的模型（如果指定）
    if args.load_model_path:
        state_dict = torch.load(args.load_model_path, map_location='cpu')
        # 处理多GPU训练保存的模型
        if all(k.startswith('module.') for k in state_dict.keys()):
            state_dict = {k[7:]: v for k, v in state_dict.items()}
        model.load_state_dict(state_dict)
        logger.info(f"加载已训练模型: {args.load_model_path}")
    
    model.to(args.device)
    
    # 多 GPU 训练
    if torch.cuda.device_count() > 1 and args.do_train:
        model = torch.nn.DataParallel(model)
        logger.info(f"使用 {torch.cuda.device_count()} 个 GPU 进行训练")
    
    # 训练
    if args.do_train:
        logger.info("准备训练数据...")
        train_examples = read_examples(args.train_data_file, args.dataset_type)
        train_features = convert_examples_to_features(train_examples, tokenizer, args, stage='train')
        train_source_ids = torch.tensor([f.source_ids for f in train_features], dtype=torch.long)
        train_attention_mask = torch.tensor([f.attention_mask for f in train_features], dtype=torch.long)
        train_labels = torch.tensor([f.label for f in train_features], dtype=torch.long)
        train_dataset = TensorDataset(train_source_ids, train_attention_mask, train_labels)
        
        # 验证集
        eval_examples = read_examples(args.eval_data_file, args.dataset_type)
        eval_features = convert_examples_to_features(eval_examples, tokenizer, args, stage='eval')
        eval_source_ids = torch.tensor([f.source_ids for f in eval_features], dtype=torch.long)
        eval_attention_mask = torch.tensor([f.attention_mask for f in eval_features], dtype=torch.long)
        eval_labels = torch.tensor([f.label for f in eval_features], dtype=torch.long)
        eval_dataset = TensorDataset(eval_source_ids, eval_attention_mask, eval_labels)
        
        # 开始训练
        save_metric = getattr(args, "save_metric", "f1")
        best_val = train(args, train_dataset, eval_dataset, model, tokenizer)
        logger.info(f"训练完成！最佳验证集 {save_metric.upper()}: {best_val:.4f}")
        
        # 训练完成后，如果需要进行评估/测试，重新加载最佳模型
        if args.do_eval or args.do_test:
            checkpoint_dir = os.path.join(args.output_dir, f'checkpoint-best-{save_metric}')
            model_path = os.path.join(checkpoint_dir, "pytorch_model.bin")
            if os.path.exists(model_path):
                logger.info(f"重新加载最佳模型用于评估: {model_path}")
                state_dict = torch.load(model_path, map_location='cpu')
                # 处理多GPU训练保存的模型
                if all(k.startswith('module.') for k in state_dict.keys()):
                    state_dict = {k[7:]: v for k, v in state_dict.items()}
                # 如果使用了DataParallel，需要先获取model.module
                model_to_load = model.module if hasattr(model, 'module') else model
                model_to_load.load_state_dict(state_dict)
                logger.info(f"已加载最佳模型权重")
            else:
                logger.warning(f"未找到最佳模型: {model_path}")
    
    # 评估
    if args.do_eval:
        logger.info("在验证集上评估...")
        eval_examples = read_examples(args.eval_data_file, args.dataset_type)
        eval_features = convert_examples_to_features(eval_examples, tokenizer, args, stage='eval')
        eval_source_ids = torch.tensor([f.source_ids for f in eval_features], dtype=torch.long)
        eval_attention_mask = torch.tensor([f.attention_mask for f in eval_features], dtype=torch.long)
        eval_labels = torch.tensor([f.label for f in eval_features], dtype=torch.long)
        eval_dataset = TensorDataset(eval_source_ids, eval_attention_mask, eval_labels)
        
        evaluate(args, model, eval_dataset, "验证集")
    
    # 测试
    if args.do_test:
        logger.info("在测试集上评估...")
        test_examples = read_examples(args.test_data_file, args.dataset_type)
        test_features = convert_examples_to_features(test_examples, tokenizer, args, stage='test')
        test_source_ids = torch.tensor([f.source_ids for f in test_features], dtype=torch.long)
        test_attention_mask = torch.tensor([f.attention_mask for f in test_features], dtype=torch.long)
        test_labels = torch.tensor([f.label for f in test_features], dtype=torch.long)
        test_dataset = TensorDataset(test_source_ids, test_attention_mask, test_labels)
        
        results = evaluate(args, model, test_dataset, "测试集")
        
        # 保存测试结果（只保存5个指标）
        test_dir = os.path.join(args.output_dir, "test_results")
        os.makedirs(test_dir, exist_ok=True)
        
        # 保存结果（只保存5个指标）
        summary = {
            "f1": results['f1'],
            "accuracy": results['accuracy'],
            "precision": results['precision'],
            "recall": results['recall'],
            "mcc": results['mcc']
        }
        
        summary_file = os.path.join(test_dir, "summary.json")
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        logger.info(f"测试结果已保存到: {test_dir}")


if __name__ == "__main__":
    main()
