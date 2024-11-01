from mp_parsing_algorithms import ParseDatabase, UserRatingsDatabase
from mp_visualization_algorithms import genre_ratings_ratios_by_gender_asLists, create_bar_plot
from matplotlib.backends.backend_pdf import PdfPages
from typing import List


def visualize_gender_rating_data(user_database : ParseDatabase, movie_database : ParseDatabase, 
                            genre_database : ParseDatabase , genres_to_disply : List[str] ,
                            ratings_per_user : UserRatingsDatabase,
                            filename : str):
    """
        Function produces an assortment of bar graphs corresponding to application database data 

    """
    pdf = PdfPages('{}.pdf'.format(filename))
    # genre indicies ->('Action', 'Comedy', 'Drama', 'Horror',  'Romance')
    # retrieve database indices of desired genres to plot
    genre_indices = [ genre_database.get_data()[x] for x in genres_to_disply ]
    
    # Loading plot data 
    #---------------Female and Male differences-----------------------------------------
    # High ratings
    dataset_Male_vs_Female_High_Ratings = genre_ratings_ratios_by_gender_asLists(
        user_database    = user_database, 
        movie_database   = movie_database,
        genre_database   = genre_database,
        ratings_per_user = ratings_per_user, 
        age_range        = [0,9999], 
        rating_range     = [4,5],
        genre_indices    = genre_indices)
    
    # Low ratings
    dataset_Male_vs_Female_Low_Ratings = genre_ratings_ratios_by_gender_asLists(
        user_database    = user_database, 
        movie_database   = movie_database,
        genre_database   = genre_database,
        ratings_per_user = ratings_per_user, 
        age_range        = [0,9999], 
        rating_range     = [1,2],
        genre_indices    = genre_indices)
    #----------------Younger and older differences--------------------------------------
    #Younger - High
    dataset_Young_High_Ratings = genre_ratings_ratios_by_gender_asLists(
        user_database    = user_database, 
        movie_database   = movie_database,
        genre_database   = genre_database,
        ratings_per_user = ratings_per_user, 
        age_range        = [20,30], 
        rating_range     = [4,5],
        genre_indices    = genre_indices)
    #Younger - Low
    dataset_Young_Low_Ratings = genre_ratings_ratios_by_gender_asLists(
        user_database    = user_database, 
        movie_database   = movie_database,
        genre_database   = genre_database,
        ratings_per_user = ratings_per_user, 
        age_range        = [20,30], 
        rating_range     = [1,2],
        genre_indices    = genre_indices)
    #Older - High
    dataset_Old_High_Ratings = genre_ratings_ratios_by_gender_asLists(
        user_database    = user_database, 
        movie_database   = movie_database,
        genre_database   = genre_database,
        ratings_per_user = ratings_per_user, 
        age_range        = [50,60], 
        rating_range     = [4,5],
        genre_indices    = genre_indices)
    #Older - Low
    dataset_Old_Low_Ratings = genre_ratings_ratios_by_gender_asLists(
        user_database    = user_database, 
        movie_database   = movie_database,
        genre_database   = genre_database,
        ratings_per_user = ratings_per_user, 
        age_range        = [50,60], 
        rating_range     = [1,2],
        genre_indices    = genre_indices)
    #-----------------------------------------------------------------------------------
    y_axis_description = 'Ratio (%) (# of target ratings) / (total # of ratings in given demographic)'
    #PLOT 1 MALE VS FEMALE (HIGH RATINGS)
    data = [
                dataset_Male_vs_Female_High_Ratings['M'],
                dataset_Male_vs_Female_High_Ratings['F']
            ]
    create_bar_plot(
        data          = data,
        x_labels      = genres_to_disply,
        y_description = y_axis_description,
        subjects      = ['Male', 'Female'], 
        title         = 'Male-to-Female (High Rating)', 
        pdf           = pdf)
    #PLOT 2 MALE VS FEMALE (LOW RATINGS)
    data = [
            dataset_Male_vs_Female_Low_Ratings['M'],
            dataset_Male_vs_Female_Low_Ratings['F']
        ]
    create_bar_plot(
        data          = data,
        x_labels      = genres_to_disply,
        y_description = y_axis_description,
        subjects      = ['Male', 'Female'], 
        title         = 'Male-to-Female (Low Rating)', 
        pdf           = pdf)
    #PLOT 3 YOUNGER VS OLDER (HIGH)
    data = [
            dataset_Young_High_Ratings['M'],
            dataset_Old_High_Ratings['M'],
            dataset_Young_High_Ratings['F'],
            dataset_Old_High_Ratings['F']      
        ]
    create_bar_plot(
        data          = data,
        x_labels      = genres_to_disply,
        y_description = y_axis_description,
        subjects      = ['Young Male', 'Old Male', 'Young Female', 'Old Female'], 
        title         = 'Young-to-Old (High Rating)', 
        pdf           = pdf)    
    #PLOT 4 YOUNGER VS OLDER (LOW)
    data = [
            dataset_Young_Low_Ratings['M'],
            dataset_Old_Low_Ratings['M'],
            dataset_Young_Low_Ratings['F'],
            dataset_Old_Low_Ratings['F']      
        ]
    create_bar_plot(
        data          = data,
        x_labels      = genres_to_disply,
        y_description = y_axis_description,
        subjects      = ['Young Male', 'Old Male', 'Young Female', 'Old Female'], 
        title         = 'Young-to-Old (Low Rating)', 
        pdf           = pdf)    
    #End visualizeData()
    pdf.close()


