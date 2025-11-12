import os
import numpy as np
# import matplotlib.pyplot as plt
# from mpl_toolkits.mplot3d import Axes3D
import time,random
from datetime import datetime
# import plotly.graph_objects as go
# from mpl_toolkits.mplot3d.art3d import Poly3DCollection


def load_3d_model(filename=None):
    """Charge un modèle 3D depuis un fichier .obj ou génère un cube simple
       filename: nom du fichier .obj à charger
       
       Retourne les noeuds et les faces en tableau numpy"""
    
    # Charger depuis un fichier .obj
    vertices = []
    faces = []
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith('v '):  # Vertex
                parts = line.split()
                x, y, z = float(parts[1]), float(parts[2]), float(parts[3])
                vertices.append([x, y, z])
            
            elif line.startswith('f '):  # Face
                parts = line.split()
                face_indices = []
                for part in parts[1:]:
                    vertex_index = int(part.split('/')[0]) - 1
                    face_indices.append(vertex_index)
                
                if len(face_indices) == 3:
                    faces.append(face_indices)
                elif len(face_indices) == 4:
                    faces.append([face_indices[0], face_indices[1], face_indices[2]])
                    faces.append([face_indices[0], face_indices[2], face_indices[3]])
        
        vertices = np.array(vertices, dtype=float)
        faces = np.array(faces) if faces else None
        
        print(f"Fichier {filename.split("/")[-1]} chargé avec succès")
        print(f"  Nombre de vertices: {len(vertices)}")
        print(f"  Nombre de faces: {len(faces) if faces is not None else 0}")
        
        return {"vertices":vertices, "faces":faces}

def save_3d_model(vertices, faces, filename):
    """Sauvegarde un modèle 3D dans un fichier .obj"""
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as file:
            for vertex in vertices:
                file.write(f"v {vertex[0]:.6f} {vertex[1]:.6f} {vertex[2]:.6f}\n")
            file.write("\n")
            
            if faces is not None:
                for face in faces:
                    file.write(f"f {face[0]+1} {face[1]+1} {face[2]+1}\n")
        
        print(f"Modèle sauvegardé dans {filename}")
    except Exception as e:
        print(f"Erreur lors de la sauvegarde: {e}")  
        

def compute_hausdorff(file1, file2):
    """
    Compare deux fichiers .obj et calcule les distances
    """
    
    # Charger les maillages
    mesh1 = load_mesh(file1)
    mesh2 = load_mesh(file2)
    
    if mesh1 is None or mesh2 is None:
        print("Erreur: Impossible de charger les maillages")
        return
    
    hausdorff = hausdorff_distance(mesh1, mesh2)

def distance_vertex_model(vertex, model) -> float:
    distance = numpy.inf
    for v in model:
        d = numpy.linalg.norm(v - vertex)
        if d < distance:
            distance = d
    return distance

def directed_hausdorff(model1, model2) -> float:
    hd = 0.0
    for i, v in enumerate(model1):
        print("vertex model1 : " + str(i))
        d = distance_vertex_model(v, model2)
        if d > hd:
            hd = d
    return hd

def hausdorff_distance(mesh1, mesh2):
    """
    Calcule la distance de Hausdorff entre deux maillages
    """
    vertices1 = mesh1.vertices
    vertices2 = mesh2.vertices
    
    # Distance de Hausdorff directionnelle de mesh1 vers mesh2
    d_forward = directed_hausdorff(vertices1, vertices2)[0]
    # Distance de Hausdorff directionnelle de mesh2 vers mesh1
    d_backward = directed_hausdorff(vertices2, vertices1)[0]
    
    # La distance de Hausdorff est le maximum des deux
    hausdorff_dist = max(d_forward, d_backward)
    
    return hausdorff_dist