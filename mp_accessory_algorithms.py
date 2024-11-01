# -*- coding: utf-8 -*-
"""
Created on Thu Oct 31 17:49:32 2024

@author: jonat
"""
from typing import List, Tuple
from mp_parsing_algorithms import UserRatingsDatabase
from mp_prediction_algorithms import pearson_correlation_coeff_similarity_prediction

def key_match(d1 : dict, d2 : dict) -> bool :
    """
        Function returns true if a key in one dictionary matches a key in another.
    """
    
    for key in d1.keys():
        if key in d2:
            return True
    return False


# IMPLEMENTATION OF MERGESORT ALGORITHM
def merge( L : List[int | float] , start : int ,mid : int , end : int ) -> None:
    if (L[mid] <= L[mid+1]):
        return
    i = start
    j = mid+1
    temp = []
    while (i <= mid) and (j <= end):
        if L[i] <= L[j]:
            temp.append(L[i])
            i += 1            
        else:
            temp.append(L[j])
            j += 1
    if j > end:
        temp.extend(L[i:mid+1])
    if i > mid:
        temp.extend(L[j:end+1])
    L[start:end+1] = temp.copy()

def mergeSort(L : List[int | float], start : int , end : int ) -> None:
    if (start>=end):
        return
    mid = start+ ( end - start ) /2
    mergeSort(L,start,mid)
    mergeSort(L,mid+1,end)
    merge(L,start,mid,end)
    
