
from mp_parsing_algorithms import ParseDatabase, RatingsDatabase, UserRatingsDatabase
from mp_parsing_algorithms import generate_user_set, generate_movie_set, generate_ratings_set
from mp_parsing_algorithms import generate_genre_set, generate_ratings_database
from mp_visualization_implementation import visualize_gender_rating_data

if __name__ == '__main__':
    user_database    : ParseDatabase       = generate_user_set()
    movie_database   : ParseDatabase       = generate_movie_set()
    genre_database   : ParseDatabase       = generate_genre_set()
    ratings_data     : ParseDatabase       = generate_ratings_set()
    ratings_database : RatingsDatabase     = generate_ratings_database(
        user_count   = user_database.get_count(),
        movie_count  = movie_database.get_count(),
        ratings_data = ratings_data
    )
    ratings_per_user : UserRatingsDatabase = ratings_database.ratings_per_user
    labels = ['Action', 'Comedy', 'Drama', 'Horror',  'Romance']
    filename = "ratings-plots"
    
    visualize_gender_rating_data(
        user_database   =  user_database,
        movie_database  =  movie_database,
        genre_database  =  genre_database,
        genres_to_disply=  labels,
        ratings_per_user=  ratings_per_user,
        filename        =  filename
    )
