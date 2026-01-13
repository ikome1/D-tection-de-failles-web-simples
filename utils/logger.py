#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Système de logging structuré pour Red Chain
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

class ColoredFormatter(logging.Formatter):
    """Formateur de logs avec couleurs ANSI"""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{log_color}{record.levelname}{self.RESET}"
        return super().format(record)

def setup_logger(
    name: str = 'redchain',
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    log_dir: str = 'logs'
) -> logging.Logger:
    """
    Configure et retourne un logger structuré
    
    Args:
        name: Nom du logger
        level: Niveau de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Nom du fichier de log (optionnel)
        log_dir: Répertoire pour les logs
    
    Returns:
        Logger configuré
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Évite les handlers dupliqués
    if logger.handlers:
        return logger
    
    # Format de log
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    console_formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Handler console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Handler fichier (si spécifié)
    if log_file:
        log_path = Path(log_dir)
        log_path.mkdir(exist_ok=True)
        
        file_path = log_path / log_file
        file_handler = logging.FileHandler(file_path, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # Log tout dans le fichier
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

def get_logger(name: str = 'redchain') -> logging.Logger:
    """
    Récupère un logger existant ou en crée un nouveau
    
    Args:
        name: Nom du logger
    
    Returns:
        Logger
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        # Si pas de handlers, configure un logger par défaut
        return setup_logger(name)
    return logger
