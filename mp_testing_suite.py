from mp_prediction_algorithms import kNearestNeighbors, random_prediction, mean_user_rating_based_prediction
from mp_prediction_algorithms import mean_movie_rating_based_prediction, demographic_based_prediction
from mp_prediction_algorithms import genre_based_prediction, hybrid_based_prediction
from mp_parsing_algorithms import generte_user_set, generte_movie_set, generte_genre_set, generate_ratings_database
from mp_parsing_algorithms import generte_ratings_set 
from mp_parsing_algorithms import RatingsDatabase, ParseDatabase, UserRatingsDatabase, MovieRatingsDatabase
from mp_math_algorithms import rmse
from typing import List
import random


def generate_rmse_values( *, actual_ratings : List[int | float], predictions : List[int | float]) -> List[float]:
    """
        Function returns a list of rmse values calculated per algorithm result data passed through the
        predictions parameter.<br>
        
        Parameters:<br>
        - <strong>actual_ratings</strong>   (<code>list</code>):   test dataset of actual ratings<br>
        - <strong>predictions</strong>      (<code>list</code>) :  training dataset of algorithmically calculated predictions<br>
        
        Returns:<br>
        - <code>list</code>: resultant rmse values
    """
    #Returns a list of calculated RMSE values
    output = []
    #For each set of predictions
    for algorithm in predictions:
        #calculate the RMSE value
        output.append(rmse(
                            actual_ratings    = actual_ratings, 
                            predicted_ratings = algorithm))    
    return output


#USAGE: GENERATE LIST OF PREDICTIONS FOR THE 5 ALGORITHMS
def generate_predictions( *, ratings_data : ParseDatabase, ratings_per_user : UserRatingsDatabase, 
                                   ratings_per_movie : MovieRatingsDatabase, 
                                   user_database : ParseDatabase, movie_database : ParseDatabase) -> dict:
    
    #list of true ratings
    actual_ratings = []
    #will provide a list of values for each algorithm implementation
    algorithm_predictions = [[] for x in range(9)]
    # similarity data per user
    similar_users = {}
    _ratings_data = ratings_data.get_data()
    # calculating similarity data for each user as encountered in ratings dataset
    for rating in _ratings_data:
        rating_entry = _ratings_data[rating]
        # has this user's similarity data been calculated ? 
        if not (rating_entry.user_id in similar_users):
            similar_users[rating_entry.user_id] = kNearestNeighbors(
                        user_id          = rating_entry.user_id,
                        ratings_per_user = ratings_per_user,
                        k                = user_database.get_count())
        #true rating
        actual_ratings.append(rating_entry.rating)
        #algorithm 1
        algorithm_predictions[0].append(random_prediction())
        #algorithm 2
        algorithm_predictions[1].append(mean_user_rating_based_prediction(
                                user_id          = rating_entry.user_id, 
                                ratings_per_user = ratings_per_user))
        #algorithm 3
        algorithm_predictions[2].append(mean_movie_rating_based_prediction(
                                movie_id          = rating_entry.movie_id, 
                                ratings_per_movie = ratings_per_movie))
        #algorithm 4
        algorithm_predictions[3].append(demographic_based_prediction(
                                user_id           = rating_entry.user_id, 
                                movie_id          = rating_entry.movie_id, 
                                user_database     = user_database, 
                                ratings_by_user   = ratings_per_user))
        #algorithm 5
        algorithm_predictions[4].append(genre_based_prediction(
                                user_id           = rating_entry.user_id, 
                                movie_id          = rating_entry.movie_id, 
                                movie_database    = movie_database, 
                                ratings_per_user  = ratings_per_user))
        #algorithm 6
        algorithm_predictions[5].append(hybrid_based_prediction(
                                user_id          = rating_entry.user_id, 
                                movie_id         = rating_entry.movie_id, 
                                ratings_per_user = ratings_per_user, 
                                similar_users    = similar_users[rating_entry.user_id][:10]))
        #algorithm 7
        algorithm_predictions[6].append(hybrid_based_prediction(
                                user_id          = rating_entry.user_id, 
                                movie_id         = rating_entry.movie_id, 
                                ratings_per_user = ratings_per_user, 
                                similar_users    = similar_users[rating_entry.user_id][:100]))
        #algorithm 8
        algorithm_predictions[7].append(hybrid_based_prediction(
                                user_id          = rating_entry.user_id, 
                                movie_id         = rating_entry.movie_id, 
                                ratings_per_user = ratings_per_user, 
                                similar_users    = similar_users[rating_entry.user_id][:500]))
        #algorithm 9
        algorithm_predictions[8].append(hybrid_based_prediction(
                                user_id          = rating_entry.user_id, 
                                movie_id         = rating_entry.movie_id, 
                                ratings_per_user = ratings_per_user, 
                                similar_users    = similar_users[rating_entry.user_id]))
        
    return { 'actual' : actual_ratings, 'predictions' :algorithm_predictions }

def partition_dataset( *, dataset : List[any], percent_tests : int ) -> dict:
    """
        Function returns a partitioned assortment of items from the passed in dataset.<br>
        The specified percent_tests parameter modulates the size of the partitions.<br>
        The function is meant to produce a training set and test set for data testing purposes.<br>
        
        Parameters:<br>
        - <strong>dataset</strong>        (<code>list</code>):  the dataset to partition<br>
        - <strong>percent_tests</strong>  (<code>int</code>) :  the percentage of dataset designated as the test set<br>
        
        Returns:<br>
        - <code>dict</code>: resulting partitions
    """
    num_items    = len(dataset)
    # This variable will indicate the number of randomly selected items to be present in the testing set.
    test_partition_size = int( num_items * ( percent_tests/100 ) )
    # Dictionary will hold the random selections for the testing set
    test_set_indicies   = {x:0 for x in random.sample(range(num_items), test_partition_size)}
    # The test set consists of the randomly selected items per indexes in  'test_set_indicies'
    test_set     = [ dataset[x] for x in test_set_indicies ]
    #the training set consists of all remaining tuples
    training_set = [ dataset[x] for x in range(num_items) if x not in test_set_indicies]
    #return resultant data structures
    return { 'train': training_set, 'test' : test_set }

#USAGE: FUNCTION TAKES THE TEMPLATED ALGORITHMS AND PRODUCES 'DEGREE' NUMBER OF PREDICTION RESULTS VIA CROSS-VALIDATION
def precision_testing(*, degree : int , test_class_size_percent : int ) -> List[any]:
    #load data structures
    user_database  = generte_user_set()
    movie_database = generte_movie_set()
    ratings        = generte_ratings_set()

    i = 0
    #Extract per algorithm data
    algorithm_data = [[] for x in range(9)]
    while (i < degree): 
        print('iteration ', i)
        # create a partition of training set and testing set
        data_set = partition_dataset(
                dataset       = ratings, 
                percent_tests = test_class_size_percent)
        print('data set partitioned')
        # create a ratings_per_user and ratings_per_movie which regards to the training set.
        training_set = generate_ratings_database(
                user_count   = user_database.get_count(), 
                movie_count  = movie_database.get_count(), 
                ratings_data = data_set['train'])
        train_ratings_per_user  = training_set.ratings_per_user
        train_ratings_per_movie = training_set.ratings_per_movie
        print('training set created')
        #Produce algorithmic predictions and actual ratings
        prediction_data       = generate_predictions(
                                    ratings_data      = data_set['test'], 
                                    ratings_per_user  = train_ratings_per_user, 
                                    ratings_per_movie = train_ratings_per_movie, 
                                    user_database     = user_database, 
                                    movie_database    = movie_database)
        actual_ratings        = prediction_data['actual']
        algorithm_predictions = prediction_data['predictions']
        print('predictions produced')
        result = (generate_rmse_values(
            actual_ratings = actual_ratings, 
            predictions    = algorithm_predictions))
        print('rmse values produced')
        algorithm_data[0].append(result[0])
        algorithm_data[1].append(result[1])
        algorithm_data[2].append(result[2])
        algorithm_data[3].append(result[3])
        algorithm_data[4].append(result[4])
        algorithm_data[5].append(result[5])
        algorithm_data[6].append(result[6])
        algorithm_data[7].append(result[7])
        algorithm_data[8].append(result[8])
        i += 1
    
    #Return testing results   
    return algorithm_data


