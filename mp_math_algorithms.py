# -*- coding: utf-8 -*-
"""
Created on Thu Oct 31 17:50:11 2024

@author: jonat
"""
from typing import Tuple, List
import math
from dataclasses import dataclass
from mp_parsing_algorithms import ParseDatabase, RatingsDatabase

def division_calculation( numerator : int , denominator : int ) -> float | None :
    if denominator:
        return float (numerator / denominator)
    else : 
        return None


@dataclass(kw_only=True, frozen=True)
class QuartileData:
    median  : float
    first_Q : float
    third_Q : float
    

def median_calculation( data : List[int | float]) -> float:
    """
        Function calculates the median of a given numerical dataset.
    """
    data.sort()
    mid = (len(data)//2)-1
    # midpoint splits two values ?
    if len(data) % 2 == 0:
        return float((data[mid] + data[mid+1])/2)
    # exact midpoint ?
    else:
        return float(data[mid])
    

def calculate_quartile_data(data : List[ int | float]) -> QuartileData :
    """
        Function returns the median, and first and third quartile of a dataset.
    """
    data.sort()
    #index middle of data
    mid = (len(data)//2)-1
    
    # median, first quartile, third quartile calulation
    
    median = median_calculation(data)
    first_Q = None
    third_Q = median_calculation(data[mid+1:])

    #mid between two values ? 
    if len(data) % 2 == 0:
        first_Q = median_calculation(data[:mid+1]) 
    #exact midpoint ?
    else:
        first_Q = median_calculation(data[:mid])
  
    return QuartileData( 
                    median  = median, 
                    first_Q = first_Q, 
                    third_Q = third_Q)
    
def calculate_per_genre_ratings_ratios_byGender(user_database : ParseDatabase, movie_database : ParseDatabase, ratings_per_user : RatingsDatabase, 
                            age_range : Tuple[int, int], rating_range  : Tuple[int, int], genre_count : int ) -> dict:
    """
        Function calculates the ratios of ratings per genre, individually for both males and females.<br>
    
        Parameters:<br>
            
            - <strong>user_database</strong>  entry format >><br> 
                located in <code>user_database.data</code>  ~ is <code>dict</code><br>
                key (user_id)<br> 
                value {"age":24, "gender":"M", "occupation":"technician", "zip":"85711"}<br>
            - <strong>movie_database</strong> entry format >><br> 
                located in <code>movie_database.data</code> ~ is <code>dict</code><br>
                key (movie_id)<br>
                value {"title":str, "release_date":str, "video_release_date":str, "IMDB_url":str,"genre":[]}<br>
            - <strong>ratings_per_user</strong>  entry format >><br>
                located in <code>ratings_per_user.user_ratings</code> ~ is <code>dict</code><br>
                key (user_id)<br>
                value {user_id: int, ratings : dict...}<br>
            - <strong>rating_range</strong>  is <code>tuple</code><br>
                at least r1 at most r2<br>
            - <strong>age_range</strong>      is <code>tuple</code><br> 
                at least age1 strictly less than age2<br>
            
        Returns:<br>
        - <code>dict</code>:  dictionary holding results for men and women
        
    """
    #for each movie genre
    ratings_count = {
                'M' : { x:0 for x in range(genre_count)},
                'F' : { x:0 for x in range(genre_count)}        
        }
    #will tally total number of ratings in the given demographic
    male_total_group_rating_count = 0
    female_total_group_rating_count = 0
    
    _user_database    = user_database.get_data()
    _movie_database   = movie_database.get_data()
    _per_user_ratings = ratings_per_user.user_ratings
    
    for user in _per_user_ratings:

        #user not in age range
        if ( not( age_range[0] <= _user_database[user].age < age_range[1]) ):
            #user_id += 1
            #User does not meet demographic age criteria.
            continue
        # gender filter
        gender = _user_database[user].gender
        if  gender == 'A' :
            male_total_group_rating_count += 1
            female_total_group_rating_count += 1
        if gender == 'F' :
            female_total_group_rating_count += 1 
        if gender == 'M' :
            male_total_group_rating_count += 1
        
        _user_ratings = _per_user_ratings[user].ratings

        for movie_id in _user_ratings:
            if ( rating_range[0] <= _user_ratings[movie_id] <= rating_range[1] ):
                # given this movie meets rating criteria, tally each genre corresponding to the movie.
                for genre in _movie_database[movie_id].genre:
                    #add to count of ratings for genre
                    if gender =='A':
                        ratings_count['M'][genre] +=  1
                        ratings_count['F'][genre] +=  1
                    else :    
                        ratings_count[gender][genre] +=  1
                # BOTTOM OF FOR (genres)
        # BOTTOM OF FOR (USER'S RATINGS)
    # BOTTOM OF FOR (RATINGS PER USER)
                            
    #if the total number of ratings provided by the subpopulation is 0, then the denominator of the fraction is 0, 
    #and the function should return None.
    if not male_total_group_rating_count: 
        ratings_count['M'] = None
    else:
        ratings_count['M'] = { x: float(ratings_count['M'][x] / male_total_group_rating_count) for x in ratings_count['M'] }
    if not female_total_group_rating_count: 
        ratings_count['F'] = None
    else:
        ratings_count['F'] = { x: float(ratings_count['F'][x] / female_total_group_rating_count) for x in ratings_count['F'] }

    return ratings_count    


#USAGE: CALCULATE THE RMSE VALUE FOR A GIVEN SET OF DATA
def rmse(*, actual_ratings : List[int | float] , predicted_ratings : List[int | float]) -> float :
    """
        Function calculates the Root Mean Square Error in relation to actuals and predictions 
        passed in as parameters<br>
        
        Parameters:<br>
        - <strong>actual_ratings</strong>       (<code>list</code>): <br> real rating values<br>
        - <strong>predicted_ratings</strong>    (<code>list</code>): <br> algorithmically predicted values<br>
        
        Returns:<br>
        - <code>float</code>: the result of rmse calculations
    """
    #The formula takes the summation of difference-between-actual-and-predicted-squared values in the data set.
    squared_summation = 0
    # variable to count the number of 'None' (n/a) predictions encountered
    omitted           = 0
    #for each potential predicted rating matched to an actual rating
    i = 0
    while(i < len(actual_ratings)):
        try: 
            squared_value     =  pow( (actual_ratings[i] - predicted_ratings[i]) ,2)
            squared_summation += squared_value
            i += 1   
        #encountered a None predicted rating
        except:
            omitted += 1
            i  += 1
    try:
        #returns the summation divided by the sample size and square rooted.
        _rmse = math.sqrt( squared_summation /( len(actual_ratings)-omitted ) )
        return _rmse
    except:
        #Calculation error: Attempting 0 division
        return None