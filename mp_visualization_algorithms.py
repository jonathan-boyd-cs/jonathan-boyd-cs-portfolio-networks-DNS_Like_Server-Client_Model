import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
from typing import List
from mp_parsing_algorithms import ParseDatabase, UserRatingsDatabase
from mp_math_algorithms import calculate_per_genre_ratings_ratios_byGender, calculate_quartile_data


def extract_list_from_dict(key_legend : List[any], d : dict):
    """
        Function extracts items at specified keys from a dictionary as ordered in
        provided key legend.<br>
        
        Parameters:<br>
        - <strong>legend</strong>   (<code>list</code>) list of keys in order desired from d<br>
        - <strong>li</strong>       (<code>dict</code>) dictionary to extract data from<br>
        
        Returns:<br>
        - list of extracted data

    """
    return  [d[key] for key in key_legend]


def create_bar_plot( data : List[List[any]], x_labels : List[str], y_description : str, subjects : List[str], 
                             title : str,  pdf : PdfPages) -> None :
    """
        Function creates a bar chart for the provided data
    """
    plt.style.use('dark_background')
    # bar height values
    means = {
                x : tuple(y*100 for y in data[idx]) for idx,x in enumerate(subjects)
            }
    # bar plotting variables
    bar_location_var = np.arange(5)
    bar_width = 0.20
    multiplier = 0

    figure, ax = plt.subplots(layout='constrained')
    
    # for each means data calculation ( creating bars/whiskers for plot )
    for subject, value in means.items():
        bar_offset = bar_width * multiplier
        bar = ax.bar(
                x      = bar_location_var + bar_offset, 
                height = value, 
                width  = bar_width,
                label  = subject)
        ax.bar_label(
                container  = bar, 
                padding    = 3, 
                fmt        = '%.3f', 
                label_type ='edge', 
                fontsize   = 5)
        multiplier = multiplier + 1
 
    # adding styling 
    
    ax.set_ylabel( y_description, fontsize=7)
    ax.set_title(label=title, fontsize = 7)
    ax.set_xticks(bar_location_var + bar_width, x_labels, fontsize=8)
    ax.legend(loc='best', ncols=2, fontsize='small')
    ax.autoscale(enable=True, axis='both', tight=None)
    
    pdf.savefig(figure)

def create_whisker_plot(data_set : List[any] , filename : str, title : str ,
                        xlabel : str , ylabel : str) -> None:
    """
        Function produces a box and whiskers chart for the provided data.
    """
    pdf = PdfPages(f'{filename}.pdf')
    
    boxes = []
    entry_number = 1
    for case in data_set:
        case.sort()
        
        # bottom whisker
        minimum = min(case)
        # top whisker
        maximum = max(case)
        # box data
        quartile_data = calculate_quartile_data(case)
        median = quartile_data.median
        Q1     = quartile_data.first_Q
        Q3     = quartile_data.third_Q 
        
        boxes.append(
            {
                'label': f"Algo-{entry_number}",
                'whislo': minimum,
                'q1': Q1,
                'med':median,
                'q3': Q3,
                'whishi': maximum 
            })
        entry_number += 1
        
    plt.rcParams.update({'axes.labelsize': 'small'})  
    figure, ax = plt.subplots()  
    #Produce chart 
    ax.bxp(boxes, showfliers=False)
    #Style Chart
    ax.yaxis.grid(True,linestyle='-',which='major',color='lightgrey',alpha=0.5)
    ax.set(axisbelow=True,title=title,xlabel=xlabel,ylabel=ylabel)
    ax.autoscale(enable=True, axis='both', tight=None)
    pdf.savefig(figure)
    pdf.close()    


def genre_ratings_ratios_by_gender_asLists(user_database : ParseDatabase, movie_database : ParseDatabase,
                                           genre_database : ParseDatabase,
                                           ratings_per_user : UserRatingsDatabase , age_range, 
                                           rating_range, genre_indices : List[int]) -> dict :
    dataset_Male_vs_Female = calculate_per_genre_ratings_ratios_byGender(
        user_database    = user_database, 
        movie_database   = movie_database,
        ratings_per_user = ratings_per_user, 
        age_range        = age_range, 
        rating_range     = rating_range,
        genre_count      = genre_database.get_count())
    dataset_Male_List   = extract_list_from_dict(genre_indices, dataset_Male_vs_Female['M'])
    dataset_Female_List = extract_list_from_dict(genre_indices, dataset_Male_vs_Female['F'])
    
    return { 'M' : dataset_Male_List, 'F' : dataset_Female_List}

