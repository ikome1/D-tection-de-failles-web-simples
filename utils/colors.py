#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codes couleur ANSI pour l'affichage dans le terminal
"""

class Colors:
    """Codes couleur ANSI pour l'affichage"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    
    # Couleurs de texte
    BLACK = '\033[30m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    
    # Couleurs de fond
    BG_BLACK = '\033[40m'
    BG_RED = '\033[101m'
    BG_GREEN = '\033[102m'
    BG_YELLOW = '\033[103m'
    BG_BLUE = '\033[104m'
    BG_MAGENTA = '\033[105m'
    BG_CYAN = '\033[106m'
    BG_WHITE = '\033[107m'
    
    @staticmethod
    def disable():
        """Désactive les couleurs (utile pour les logs fichiers)"""
        Colors.RESET = ''
        Colors.BOLD = ''
        Colors.DIM = ''
        Colors.ITALIC = ''
        Colors.UNDERLINE = ''
        Colors.BLACK = ''
        Colors.RED = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.BLUE = ''
        Colors.MAGENTA = ''
        Colors.CYAN = ''
        Colors.WHITE = ''
        Colors.BG_BLACK = ''
        Colors.BG_RED = ''
        Colors.BG_GREEN = ''
        Colors.BG_YELLOW = ''
        Colors.BG_BLUE = ''
        Colors.BG_MAGENTA = ''
        Colors.BG_CYAN = ''
        Colors.BG_WHITE = ''
