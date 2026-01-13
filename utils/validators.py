#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Validateurs pour les entrées utilisateur
"""

import re
import socket
from typing import Optional, List
from ipaddress import ip_address, ip_network, AddressValueError

class ValidationError(Exception):
    """Exception levée lors d'une erreur de validation"""
    pass

def validate_ip(ip: str) -> bool:
    """
    Valide une adresse IP
    
    Args:
        ip: Adresse IP à valider
    
    Returns:
        True si valide, False sinon
    """
    try:
        ip_address(ip)
        return True
    except (ValueError, AddressValueError):
        return False

def validate_domain(domain: str) -> bool:
    """
    Valide un nom de domaine
    
    Args:
        domain: Nom de domaine à valider
    
    Returns:
        True si valide, False sinon
    """
    if not domain or len(domain) > 255:
        return False
    
    # Pattern basique pour nom de domaine
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_target(target: str) -> str:
    """
    Valide une cible (IP ou domaine) et retourne l'IP résolue
    
    Args:
        target: Cible à valider (IP ou domaine)
    
    Returns:
        IP résolue
    
    Raises:
        ValidationError: Si la cible est invalide
    """
    if not target or not isinstance(target, str):
        raise ValidationError("La cible doit être une chaîne non vide")
    
    target = target.strip()
    
    # Test si c'est une IP
    if validate_ip(target):
        return target
    
    # Test si c'est un domaine
    if validate_domain(target):
        try:
            ip = socket.gethostbyname(target)
            return ip
        except socket.gaierror:
            raise ValidationError(f"Impossible de résoudre le domaine: {target}")
    
    raise ValidationError(f"Cible invalide: {target} (doit être une IP ou un domaine valide)")

def validate_port(port: int) -> bool:
    """
    Valide un numéro de port
    
    Args:
        port: Numéro de port à valider
    
    Returns:
        True si valide (1-65535), False sinon
    """
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False

def validate_ports(ports: List[int]) -> List[int]:
    """
    Valide une liste de ports
    
    Args:
        ports: Liste de ports à valider
    
    Returns:
        Liste de ports valides
    
    Raises:
        ValidationError: Si un port est invalide
    """
    valid_ports = []
    for port in ports:
        if not validate_port(port):
            raise ValidationError(f"Port invalide: {port} (doit être entre 1 et 65535)")
        valid_ports.append(int(port))
    
    return valid_ports

def validate_port_range(port_str: str) -> List[int]:
    """
    Parse et valide une chaîne de ports (ex: "21,22,80-100,443")
    
    Args:
        port_str: Chaîne de ports à parser
    
    Returns:
        Liste de ports valides
    
    Raises:
        ValidationError: Si le format est invalide
    """
    ports = []
    
    for part in port_str.split(','):
        part = part.strip()
        
        if '-' in part:
            # Plage de ports (ex: 80-100)
            try:
                start, end = part.split('-')
                start, end = int(start.strip()), int(end.strip())
                
                if not validate_port(start) or not validate_port(end):
                    raise ValidationError(f"Plage de ports invalide: {part}")
                
                if start > end:
                    raise ValidationError(f"Plage de ports invalide: {part} (début > fin)")
                
                ports.extend(range(start, end + 1))
            except ValueError:
                raise ValidationError(f"Format de plage invalide: {part}")
        else:
            # Port unique
            try:
                port = int(part)
                if not validate_port(port):
                    raise ValidationError(f"Port invalide: {port}")
                ports.append(port)
            except ValueError:
                raise ValidationError(f"Port invalide: {part}")
    
    # Supprime les doublons et trie
    return sorted(list(set(ports)))
