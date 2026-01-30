# model.py
import torch
import torch.nn as nn
from transformers import AutoModel, AutoConfig, AutoTokenizer


class UniXcoderForVulDetection(nn.Module):
    def __init__(self, model_name_or_path, num_labels=2):
        """
        Initialize UniXcoder vulnerability detection model
        
        Parameters:
            model_name_or_path: Pretrained model name or path
            num_labels: Number of labels
        """
        super().__init__()
        
        # Load UniXcoder model
        self.unixcoder = AutoModel.from_pretrained(model_name_or_path)
        self.config = self.unixcoder.config
        
        # Classification head
        self.dropout = nn.Dropout(0.1)  # Add dropout to prevent overfitting
        self.classifier = nn.Linear(self.config.hidden_size, num_labels)
        
        # Initialize classification head weights
        self.classifier.weight.data.normal_(mean=0.0, std=0.02)
        if self.classifier.bias is not None:
            # Initialize bias as small random values to avoid initial prediction bias toward a class
            self.classifier.bias.data.normal_(mean=0.0, std=0.02)
        
        # Class weights (optional)
        self.class_weights = None
        
    def set_class_weights(self, weights):
        """Set class weights"""
        self.class_weights = weights
        
    def forward(
            self,
            input_ids=None,
            attention_mask=None,
            labels=None,
            return_dict=True
    ):
        # UniXcoder encoding
        outputs = self.unixcoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_hidden_states=True,
            return_dict=return_dict
        )
        
        # Use [CLS] token
        pooled_output = outputs.last_hidden_state[:, 0, :]
        pooled_output = self.dropout(pooled_output)
        logits = self.classifier(pooled_output)
        
        loss = None
        if labels is not None:
            if self.class_weights is not None:
                # Ensure weights are on correct device
                weights = self.class_weights.to(logits.device)
                loss_fct = nn.CrossEntropyLoss(weight=weights)
            else:
                loss_fct = nn.CrossEntropyLoss()
            loss = loss_fct(logits.view(-1, self.classifier.out_features), labels.view(-1))
        
        if return_dict:
            return {
                "loss": loss,
                "logits": logits,
                "hidden_states": outputs.hidden_states,
            }
        return (loss, logits) if loss is not None else (logits,)
    
    def predict(self, input_ids, attention_mask=None):
        """Prediction method"""
        with torch.no_grad():
            outputs = self(
                input_ids=input_ids, 
                attention_mask=attention_mask, 
                return_dict=True
            )
            logits = outputs['logits']
            probabilities = torch.softmax(logits, dim=-1)
            predictions = torch.argmax(logits, dim=-1)
            
        return predictions, probabilities
