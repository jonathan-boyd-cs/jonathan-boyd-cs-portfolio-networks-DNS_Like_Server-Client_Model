import random
from typing import List, Tuple
from mp_parsing_algorithms import UserRatingsDatabase, MovieRatingsDatabase, ParseDatabase
from mp_math_algorithms import division_calculation
from mp_accessory_algorithms import key_match, mergeSort

def random_prediction() -> int :
    """
        Function acts as a basic unintelligent ratings prediction generator.<br>
        
        Returns:<br>
        - <code>int</code>: random integer between 1 and 5 inclusive
    """
    return (random.randint(1,5))

def mean_user_rating_based_prediction(user_id : int , ratings_per_user : UserRatingsDatabase) -> float | None :
    """.
        Function returns the average rating a given user has provided.<br>
        
        Parameters:<br>
        - <strong>user_id</strong>          (<code>int</code>)                : user in question for prediction<br>
        - <strong>ratings_per_user</strong> (<code>UserRatingsDatabase</code>): ratings per user dataset<br>
        
        Returns:<br>
        - <code>float</code>: the average rating the user has provided
    """
    try:
        user_ratings = ratings_per_user.user_ratings[user_id].ratings.values()
        summation_of_ratings = sum(user_ratings)
        total_number_ratings = len(user_ratings)
        return division_calculation( summation_of_ratings , total_number_ratings ) 
    except:
        # no ratings to observe or unknown error
        return None

def mean_movie_rating_based_prediction( movie_id : int ,ratings_per_movie : MovieRatingsDatabase) -> float | None:
    """.
        Function returns the average rating a given movie has received.<br>
        
        Parameters:<br>
        - <strong>movie_id</strong>         (<code>int</code>)                : movie in question for prediction<br>
        - <strong>ratings_per_movie</strong>(<code>MovieRatingsDatabase</code>): ratings per movie dataset<br>
        
        Returns:<br>
        - <code>float</code>: the average rating the user has provided
    """
    try:
        movie_ratings = ratings_per_movie.movie_ratings[movie_id].ratings.values()
        summation_of_ratings = sum(movie_ratings)
        total_number_ratings = len(movie_ratings)
        return division_calculation( summation_of_ratings , total_number_ratings )
    except:
        # no ratings to observe or unknown error
        return None
    
def demographic_based_prediction(user_id : int , movie_id : int , user_database : ParseDatabase,
                                 ratings_by_user : UserRatingsDatabase) -> float | None:
    """
        Returns the average rating a given movie has received by people like a given user, based on 
        demographic data... here, the demographic in common with the provided <code>user_id</code>.<br>
        Function calculates the average ratings for a specified <code>movie_id</code> amongst individuals 
        within 5 years of the age of the user, specified by <code>user_id</code>, and the same gender of such 
        user.<br>
        
        Parameters:<br>
        -<strong>user_id</strong>           (<code>int</code>)<br> user detailing demographic and prediction<br> 
        -<strong>movie_id</strong>          (<code>int</code>)<br> movie that prediction is based off of<br>
        -<strong>user_database</strong>     (<code>ParseDatabase</code>)<br> database of user information<br>
        -<strong>ratings_by_user</strong>   (<code>UserRatingsDatabase</code>)<br> ratings as collected for each user
        
        Returns:<br>
        - the average rating for <code>movie_id</code> given a demographic corresponding to <code>user_id</code>
        
    
    """
    _user_database   = user_database.get_data()
    _ratings_by_user = ratings_by_user.user_ratings
     
    #subset G of users with age in specified age range of user_id and same gender as user_id
    gender_filter  = _user_database[user_id].gender
    age_filter     = _user_database[user_id].age
    
    #variables to calculate mean of all ratings that users in subset group G have provided for movie_id
    summation_of_ratings = 0
    total_number_ratings = 0
    #Attempt to calculate mean
    for user in _ratings_by_user:
        #subset should not contain subject user (user_id)
        if user == user_id: 
            continue
        #did not rate this movie ?
        if not movie_id in _ratings_by_user[user].ratings:
            continue
        #checking that user in question is of age and gender requirements
        if not age_filter-5 <= _user_database[user].age < age_filter+6 : 
            continue
        if not _user_database[user].gender == gender_filter: 
            continue
        #adding this user's rating for the movie, movie_id, to summation
        summation_of_ratings += _ratings_by_user[user][movie_id]
        #adding to total count of ratings given by the subset group
        total_number_ratings += 1
    
    #return mean rating - returns None if total_number_ratings == 0
    return division_calculation( summation_of_ratings , total_number_ratings )


def genre_based_prediction(user_id : int , movie_id : int , movie_database : ParseDatabase , 
                           ratings_per_user : UserRatingsDatabase) -> float | None :
    """
        Function returns the average rating that a user has given for movies of a genre 
        equivalent to the movie in question for prediction.<br>
        
        Parameters:<br>
        - <strong>user_id</strong>            (<code>int</code>)                : user in question<br> 
        - <strong>move_id</strong>            (<code>int</code>)                : movie for which prediction is desired<br>
        - <strong>movie_database</strong>     (<code>ParseDatabase</code>)      : database of movies<br>
        - <strong>ratings_per_user</strong>   (<code>UserRatingsDatabase</code>): ratings as collected per user<br>
        
        Returns:<br>
        - <code>float</code>: the average rating the user provided for movies of the same genre as movie_id
    """
    # subset M of movies with same genre as movie movie_id
    # variables to calculate mean of ratings given the subset M
    summation_of_ratings = 0
    total_number_ratings = 0
    
    _movie_database   = movie_database.get_data()
    _ratings_by_user = ratings_per_user.user_ratings[user_id].ratings
    
    m_genre = _movie_database[movie_id].genre
    #Attempt to calculate mean
    
    #looking through all of the users ratings.
    for movie in _ratings_by_user:
        #subject movie (movie_id) not in the subset
        if movie == movie_id: 
            continue
    
        #If the movie in question is of the same genre as the target movie m
        if key_match(d1=m_genre, d2=_movie_database[movie].genre):
            #adding the value of rating the user gave this movie
            summation_of_ratings += _ratings_by_user[movie]
            #adding total number of ratings in subset
            total_number_ratings += 1
        
    #return mean rating - returns None if total_number_ratings == 0
    return division_calculation( summation_of_ratings , total_number_ratings )

def pearson_correlation_coeff_similarity_prediction( user_id : int , alt_user_id : int , 
                                    ratings_per_user : UserRatingsDatabase) -> float | None :
    """
        Function implements the Pearson correlation coefficient formula to predict a given
        users tastes and subsequent movie rating prediction.<br>
        Function forms a prediction based of the of the strength of similarity between a user and 
        other users.<br>
        
        Parameters:<br>
        - <strong>user_id</strong>          (<code>int</code>): user in question<br>
        - <strong>alt_user_id</strong>      (<code>int</code>): user matched against<br>
        - <strong>ratings_per_user</strong> (<code>UserRatingsDatabase</code>): database of ratings per user<br>
        
        Returns:<br>
        - <code>float</code> the calculated prediction as determined via the pearson correlation coefficient algorithm.
    """
    _ratings_per_user = ratings_per_user.user_ratings
    try:
        X = _ratings_per_user[user_id].ratings.values()
        Y = _ratings_per_user[alt_user_id].ratings.values()
        X_user_Mean_Rating      = float( sum(X)  / len(X) )
        Y_alt_user_Mean_Rating  = float( sum(Y) /  len(Y) )
    except:
        # arithmetic error or unknown
        return 0.0
    
    cov_summation_Pearson = 0.0
    stddev_summation_Pearson_X = 0.0
    stddev_summation_Pearson_Y = 0.0

    for movie_id in _ratings_per_user[user_id]:
        if movie_id in _ratings_per_user[alt_user_id]:

            dev_value_X = (_ratings_per_user[user_id][movie_id] - X_user_Mean_Rating)
            dev_value_Y = (_ratings_per_user[alt_user_id][movie_id] - Y_alt_user_Mean_Rating)

            cov_summation_Pearson += float(  dev_value_X  *  dev_value_Y  )
            stddev_summation_Pearson_X += float( pow( dev_value_X ,2 ))
            stddev_summation_Pearson_Y += float( pow( dev_value_Y,2 ))
    
    stddev_Pearson_X = float(pow(stddev_summation_Pearson_X,0.5))
    stddev_Pearson_Y = float(pow(stddev_summation_Pearson_Y,0.5))
    
    if cov_summation_Pearson==0:
        return 0.0
        
    return division_calculation(  (cov_summation_Pearson)  , (stddev_Pearson_X*stddev_Pearson_Y)  )


# IMPLEMENTATION OF K-NEAREST NEIGHBORS 
# WILL RETURN THE K MOST SIMILAR (IN REGARDS TO MOVIE TASTES) USERS TO U
def kNearestNeighbors(user_id : int , ratings_per_user : UserRatingsDatabase, k : int ) -> List[Tuple[ int , float]]:
    """
        Function implements the K-NearestNeighbors algorithm to determine k most similar users, in terms of 
        movie ratings/taste, to the specified user_id.<br>
        Returns a list of tuples containing neighbor id's and their similarity scores.<br>
        
        Parameters:<br>
        - <strong>user_id</strong>            (<code>int</code>):                 the user in question<br>
        - <strong>ratings_per_user</strong>   (<code>UserRatingsDatabase</code>): database of ratings as collected per user <br>
        - <strong>k</strong>                  (<code>int</code>):                 number of neighbors desired<br>
    
        Returns:<br>
        - <code>list</code> list of tuples of  neighbor id's and their similarity scores
    """
    
    # Output list will be in form [(userID, similarity),...]
    output = []
    # Buffer will hold all similary matchups between user user_id and other users... [(similarity, alt_user),...]
    buffer = []
    # iteration variable (other user ids)
    alt_user = 1
    while alt_user <= ratings_per_user.user_count :
        # not considering similarity of user_id to self
        if alt_user == user_id:
            alt_user += 1
            continue
        # adding the similarity value between u and j and sort for future optimal choice selection
        taste_similarity = pearson_correlation_coeff_similarity_prediction( 
                                            user_id           = user_id,
                                            alt_user_id       = alt_user,
                                            ratings_per_user  = ratings_per_user)
        buffer.append((taste_similarity, alt_user))
        alt_user += 1
        
    # sorting all data by highest similarity then user_id decreasing
    buffer.sort(reverse=True)
    similarity_score = buffer[0][0]
    
    # now sort at each similarity value from lowest user_id to highest
    _from = 0
    to   = 0
    for neighbor in buffer:
        # seeking range of equal similarity values...
        if not (neighbor[0] == similarity_score):
            similarity_score = neighbor[0]
            # sort up to cutoff such that sorted by similarity value, then id increasing
            mergeSort(buffer,_from,to-1)
            # advance
            _from = to
            # enough neighbors processed ?
            if to >= k: 
                break
        to += 1
    
    #iteration variable
    i = 0
    #adding k "neighbors" to output list
    while (k > 0) and ( i < len(buffer) ):
        #add most similar neighbor to output in form (id, similarity_score)
        output.append((buffer[i][1],buffer[i][0]))
        k -= 1
        i += 1
    return output

def hybrid_based_prediction(user_id : int , movie_id : int , ratings_per_user : UserRatingsDatabase,
                       similar_users : List[Tuple[int , float]]) -> float:
    """
        Function utilizes the pearson correlation coefficient algorithm , prediction residuals, and k-nearest neighbors algorithm
        to calculate a given users likely rating for a movie.<br>
        Makes a movie prediction based on calculated movie taste similarities amongst the user database.<br>
        
        (!!) Function paired with output of k-nearest neighbors algorithm above... (similar_users)
        
        Parameters:<br>
        - <strong>user_id</strong>          (<code>int</code>): user in question <br>
        - <strong>movie_id</strong>         (<code>int</code>):    movie corresponding to prediction <br>
        - <strong>ratings_per_user</strong> (<code>UserRatingsDatabase</code>): database of ratings per user<br>
        - <strong>similar_users</strong>    (<code>list</code>): similarity data for some number of users in relation to user_id<br>
        
        Returns:<br>
        - <code>float</code>: the predicted movie rating of the user
    """
    _ratings_per_user = ratings_per_user.user_ratings
    
    #average rating user_id has given
    user_mean_rating = division_calculation( sum(_ratings_per_user[user_id].ratings.values())   , len(_ratings_per_user[user_id].ratings.values()))
    if not user_mean_rating:
        # div by zero
        return None
    
    
    numerator_summation = 0.0
    denominator_summation = 0.0
    
    for alt_user, similarity in similar_users:
        # Has the alt_user rated the movie ?
        if movie_id in _ratings_per_user[alt_user].ratings:
            # prediction calculations
            alt_user_rating      = _ratings_per_user[alt_user].ratings[movie_id]
            alt_user_mean_rating = division_calculation(  sum(_ratings_per_user[alt_user].ratings.values()) , len(_ratings_per_user[alt_user].ratings.values())  )
            residual             = float(alt_user_rating - alt_user_mean_rating)
            numerator_summation   += float( residual * similarity  )
            denominator_summation +=  abs(similarity)
    #empty similar_users subset
    if not denominator_summation: 
        return alt_user_mean_rating
    
    result = float( user_mean_rating + float( numerator_summation / denominator_summation ) )
    return result



