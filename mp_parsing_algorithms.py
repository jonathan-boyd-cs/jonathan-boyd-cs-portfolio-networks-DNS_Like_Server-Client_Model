#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 31 17:50:38 2024

@author: jonat
"""
from dataclasses import dataclass , field
from file_handling import file_reader
from typing import List
from collections.abc import Callable
from io import TextIOWrapper


@dataclass (kw_only=False, frozen=False)
class ParseDatabase:
    """
    
    """
    __count      : int    = 0
    __data       : dict   = field(default_factory=dict)

    def add( self, *, id : int , data : any ) -> None :
        self.__data[id] = data
        self.__count += 1
    
    def get_data(self) -> dict :
        return self.__data

    def get_count(self) -> dict :
        return self.__count
    
    def override_data( self, data : dict ) -> None:
        self.__data = data


def generate_dataset( file_handle : TextIOWrapper , parser : Callable[[str], any] ) -> ParseDatabase:
    """ 
        Function generates a list of parsed data containers given the provided parameters.<br>
        Function assumes user stores data in the dedicated 
        <code>./ml-100k/</code> directory, with data oriented as 
        presently formatted in the default implementaton.<br>
        
        Returns:<br>
        - <code>List</code>: list of user information
    """
    #the function returns a database with a dictionary containing parsed data objects
    database =  ParseDatabase()
    entry_number = 1
    #The operation will proceed until eof (~ None returned from reader)
    nline_of_data_file = file_reader(file_handle)
    while(nline_of_data_file):
        data  = parser(nline_of_data_file)
        #not observing data
        if not data: 
            continue
        else:
            database.add(id=entry_number, data=data)
            entry_number += 1
            
        nline_of_data_file = file_reader(file_handle)
    # end while -- eof
    return database



#### USER DATA FILE PARSING FUNCTIONS
@dataclass (kw_only=True, frozen=True)
class UserData:
    """
    
    """
    age        : int
    gender     : str






def user_datafile_parser( data_feed : str ) -> UserData | None :
    """
        Function parses a line expected from the <code>'./ml-100k/u.users'</code>
        file, returning a <code>UserData</code> object if proper data is passed in.<br>
    
        ~ Function assumes user stores user data in the dedicated ./ml-100k/
        directory, in the file named 'u.users' as presently formatted.<br>
        
        Parameters:<br>
        - <strong>data_feed</strong> (<code>str</code>): line read from data user file<br>
        
        Returns:<br>
        - <code>UserData</code> or <code>None</code> 
    
    """
    # not observing data per known data file format (see ./ml-100k/u.users)
    if not data_feed[0].isdigit(): 
        return None
    
    # user data format "ID|AGE|GENDER|OCCUPATION|ZIP CODE\n"
    
    # stripping out newline char
    data_feed = data_feed[:len(data_feed)-1]
    
    # splitting at data entries for parsing...
    data_feed = data_feed.split("|")
    
    # load parsed results
    user_data_parsed = UserData(
                age        = int(data_feed[1]),
                gender     = data_feed[2]
        )
    return user_data_parsed


def generate_user_set() -> List[UserData]:
    """ 
        Function decorates the generate_dataset function<br>
        
        Returns:<br>
        - <code>List</code>: list of user information
    """
    #Create file handle attached to user dataset
    file_handle = open('ml-100k/u.users' , 'r')
    return generate_dataset(
                file_handle = file_handle, 
                parser      = user_datafile_parser)

#### MOVIE DATA FILE PARSING FUNCTIONS
@dataclass (kw_only=True, frozen=True)
class MovieData:
    title              : str 
    release_date       : str 
    video_release_date : str 
    IMDB_url           : str 
    genre              : dict = field(default_factory=dict, init=True)

def movie_datafile_parser( data_feed : str ) -> MovieData | None :
    """ 
        Function parses a line expected from the <code>'./ml-100k/u.movies'</code>
        file, returning a <code>MovieData</code> object if proper data is passed in.<br>
    
        ~ Function assumes user stores movie data in the dedicated ./ml-100k/
        directory, in the file named 'u.movies' as presently formatted.<br>
        
        Parameters:<br>
        - <strong>data_feed</strong> (<code>str</code>): line read from data movie file<br>
        
        Returns:<br>
        - <code>MovieData</code> or <code>None</code> 
    """
    if not data_feed[0].isdigit(): 
        return None
    
    # movie data format "ID|MOVIE TITLE WITH YEAR| RELEASE DATE||URL(YEAR)| GENRE CODE\n"
    
    # stripping out newline char
    data_feed = data_feed[:len(data_feed)-1]
    
    # Create a wedge between <primary movie data> and <GENRE CODE> for parsing
    # See ('./ml-100k/u.movies')
    genre_code = data_feed[len(data_feed)-37:]
    movie_data = data_feed[:len(data_feed)-38]
    
    # segment movie data for parsing
    movie_data = movie_data.split('|')
    
    #convert genre code to encoded list of integer 1 or 0 values
    genre_code =  [int(x) for x in genre_code.replace('|', "")]
    
    # parsing...
    #current movie_data format... 
    # "[ID,MOVIE TITLE WITH YEAR, RELEASE DATE,VIDEO RELEASE DATE,URL(YEAR)"
    
    title = movie_data[1]
    release = movie_data[2]
    video_release_date = movie_data[3]
    url = movie_data[4]

    # load parsed results
    movie_data_parsed = MovieData(
            title              = title, 
            release_date       = release, 
            video_release_date = video_release_date, 
            IMDB_url           = url, 
            genre              = {i : 1 for i, x in enumerate(genre_code) if x}
        
        )
   
    return movie_data_parsed
        

def generate_movie_set():
    """ 
        Function decorates the generate_dataset function<br>
        
        Returns:<br>
        - <code>List</code>: list of movie information
    """
    #create file handler attached to movie dataset
    file_handle = open('ml-100k/u.movies', 'r', encoding='windows-1252')
    return generate_dataset(
                file_handle = file_handle, 
                parser      = movie_datafile_parser)

#### RATINGS DATA FILE PARSING FUNCTIONS
@dataclass (kw_only=True, frozen=True)
class RatingData:
    user_id   : int
    movie_id  : int
    rating    : int

@dataclass (kw_only=True, frozen=False)
class UserRatings:
    user_id   : int
    ratings   : dict  = field(default_factory=dict, init=False)
    
@dataclass (kw_only=True, frozen=False)
class MovieRatings:
    movie_id   : int
    ratings    : dict  = field(default_factory=dict)    


class UserRatingsDatabase:
    def __init__(self, *, user_count : int) :
        self.user_count   = user_count
        self.user_ratings =  { (x+1) : UserRatings( user_id=(x+1)) 
                               for x in range(user_count)   
                             }

class MovieRatingsDatabase:
    def __init__(self, *, movie_count : int) :
        self.movie_count   = movie_count
        self.movie_ratings =  { (x+1) : MovieRatings( movie_id=(x+1)) 
                               for x in range(movie_count)   
                             }

@dataclass (kw_only=True, frozen=False)
class RatingsDatabase:
    ratings_per_user  : UserRatingsDatabase
    ratings_per_movie : MovieRatingsDatabase
    
def ratings_datafile_parser(data_feed : str ) -> RatingData | None :
    """ 
        Function parses a line expected from the <code>'./ml-100k/u.ratings'</code>
        file, returning a <code>RatingsData</code> object if proper data is passed in.<br>
    
        ~ Function assumes user stores ratings data in the dedicated ./ml-100k/
        directory, in the file named 'u.ratings' as presently formatted.<br>
        
        Parameters:<br>
        - <strong>data_feed</strong> (<code>str</code>): line read from data ratings file<br>
        
        Returns:<br>
        - <code>RatingsData</code> or <code>None</code> 
    """
    if not data_feed[0].isdigit(): 
        return None
    
    # rating data format  "USER-ID    MOVIE-ID    RATING   TIME-STAMP\n"

    
    # stripping out newline char
    data_feed = data_feed[:len(data_feed)-1]

    #split on white space for parsing
    data_feed = data_feed.split()
    
    # omit time stamp (not used)
    data_feed.pop()
    
    #current rating data format  ["USER-ID","MOVIE-ID","RATING"]
    
    #format as integers
    data_feed = [int(x) for x in data_feed]
    

    # load parsed data
    rating_data_parsed = RatingData(
            user_id     = data_feed[0], 
            movie_id    = data_feed[1], 
            rating      = data_feed[2]
        )
   
    return rating_data_parsed

def generate_ratings_set():
    """ 
        Function decorates the generate_dataset function<br>
        
        Returns:<br>
        - <code>List</code>: list of movie information
    """
    #create file handler attached to ratings dataset
    file_handle = open('ml-100k/u.ratings', 'r')
    return generate_dataset(
                file_handle = file_handle, 
                parser      = ratings_datafile_parser)
       
def generate_ratings_database(user_count : int, movie_count : int, ratings_data : ParseDatabase) -> RatingsDatabase:
    """ 
        Function parses out ratings data and compartmentalizes the data per user and per movie,
        returning the resultant data structure.<br>
        
        Parameters:<br>
        - <strong>user_count</strong>   (<code>int</code>)  number of users in data set<br>
        - <strong>movie_count</strong>  (<code>int</code>)  number of movies in data set<br>
        - <strong>ratings_data</strong> (<code>list</code>) ratings as loaded from generate_ratings_set<br>
    
        Returns:<br>
        - <code>RatingsDatabase</code> database containing ratings data per user and per movie
    """
    ratings_per_user   = UserRatingsDatabase(user_count   = user_count  )
    ratings_per_movie  = MovieRatingsDatabase(movie_count = movie_count )

    ratings_database = RatingsDatabase(  
                ratings_per_user  = ratings_per_user,
                ratings_per_movie = ratings_per_movie
                )
    
    # ratings_data format: [{ user_id : int, movie_id : int, rating : int }...]
    # for each rating...
    for i in range(ratings_data.get_count()):
        # extract data for entries
        i += 1
        user_id   =  ratings_data.get_data()[i].user_id 
        movie_id  =  ratings_data.get_data()[i].movie_id
        rating    =  ratings_data.get_data()[i].rating
        #---ratings-per-user-update-------------------------------------------------------------------------
        ratings_database.ratings_per_user.user_ratings[ user_id ].ratings[  movie_id  ]  = rating
        #---ratings-per-movie-update-------------------------------------------------------------------------
        ratings_database.ratings_per_movie.movie_ratings[ movie_id ].ratings[  user_id  ] = rating
        #--------------------------------------------------------------------------------
    return ratings_database

#### GENRE DATA FILE PARSING FUNCTIONS

@dataclass (kw_only=True, frozen=True)
class GenreData:
    name : str
    
def genre_datafile_parser( data_feed : str ) -> GenreData | None :
    """ 
        Function parses a line expected from the <code>'./ml-100k/u.genres'</code>
        file, returning a <code>GenreData</code> object if proper data is passed in.<br>
    
        ~ Function assumes user stores genre data in the dedicated ./ml-100k/
        directory, in the file named 'u.genres' as presently formatted.<br>
        
        Parameters:<br>
        - <strong>data_feed</strong> (<code>str</code>): line read from data genres file<br>
        
        Returns:<br>
        - <code>GenreData</code> or <code>None</code> 
    """
    if not data_feed[0].isalpha(): 
        None
        
    # genre data format  "genre_name|code_int\n"
    
    # stripping out newline char
    data_feed = data_feed.strip('\n')
    
    # splitting for parsing
    data_feed = data_feed.split("|")
    
    # extract name for genre
    genre_name = data_feed[0]
    
    return GenreData( name = genre_name )
   

#USAGE: PRODUCES A LIST OF MOVIE GENRES IN ACCORDANCE WITH dataset
def generate_genre_set():
    #create file handler attached to rating dataset
    file_handle = open('ml-100k/u.genres', 'r')
    genre_data = generate_dataset(
                file_handle = file_handle, 
                parser      = genre_datafile_parser)
    
    genres = { genre_data.get_data()[x].name : idx 
              for idx, x in enumerate(list(genre_data.get_data().keys()))}

    genre_data.override_data(genres)
    return genre_data        
    