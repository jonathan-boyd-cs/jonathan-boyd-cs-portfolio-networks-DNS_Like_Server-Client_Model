
from mp_visualization_algorithms import create_whisker_plot
from mp_testing_suite import precision_testing

if __name__ == '__main__':
    algorithm_data = precision_testing(
                degree                  = 10, 
                test_class_size_percent = 20)
    create_whisker_plot(
                data_set  = algorithm_data, 
                filename  = "predictions-whiskers",
                title     = "Prediction Algorithm Comparisons",
                xlabel    = "Algorithms",
                ylabel    = "RMSE Calculation")
