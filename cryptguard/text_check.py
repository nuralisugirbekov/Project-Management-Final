from langdetect import detect, DetectorFactory
from nltk.tokenize import word_tokenize
import nltk
from nltk.corpus import words

DetectorFactory.seed = 0

nltk.download('punkt')
nltk.download('punkt_tab')
nltk.download('words')
english_words = set(words.words())


def is_human_readable(text):
    try:
        words = word_tokenize(text.lower())

        recognized_dict_words = set(words) & english_words

        dict_word_ratio = len(recognized_dict_words) / len(words) if words else 0

        return dict_word_ratio > 0.5
    except:
        return False
