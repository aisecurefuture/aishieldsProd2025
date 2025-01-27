from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

import nltk
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer

import string
import os
import fickling


class Prompt_Injection_Sanitizer:
	def __init__(self, modelFilepath, vectorizerFilepath):
		self.vectorizer = fickling.load(open(vectorizerFilepath,'rb'))
		self.model = fickling.load(open(modelFilepath,'rb'))
	
	#returns the probability that a input prompt contains a particular prompt injection identifier
	def get_confidence(self, input_prompt:str):
		vectors = self.vectorizer.transform([input_prompt])
		return self.model.predict_proba(vectors)[0][1]


def pre_proecess_prompt(prompt:str):
    stemmer = PorterStemmer()
    stopwords_set = set(stopwords.words('english'))
    text = prompt.lower()
    text = text.translate(str.maketrans('','', string.punctuation)).split()
    text = [stemmer.stem(word) for word in text if word not in stopwords_set]
    prompt = " ".join(text)
    return prompt



def prompt_injection_score(input_str:str):
    try:
        module_path = os.path.dirname(__file__)
        basepath = f"{module_path}/"
        scores = {
            "jailbreak_score": 0,
            "malicious_request_score": 0
        }
        jb_model_path = os.path.join(basepath, "models/jailbreak_model.bin")
        jb_vector_path = os.path.join(basepath, "models/jailbreak_vectorizer.bin")
        mr_model_path = os.path.join(basepath, "models/malicious_request_model.bin")
        mr_vector_path = os.path.join(basepath, "models/malicious_request_vectorizer.bin")
        jailbreak_detector = Prompt_Injection_Sanitizer(jb_model_path, jb_vector_path)
        malicious_request_detector = Prompt_Injection_Sanitizer(mr_model_path, mr_vector_path)
        input_str = pre_proecess_prompt(input_str)
        scores["jailbreak_score"] = jailbreak_detector.get_confidence(input_str)
        scores["malicious_request_score"] = malicious_request_detector.get_confidence(input_str)

        return scores
    except Exception as err:
        print('an error occured in prompt_injection_sanitizer: ' + str(err))
        scores = {
            "jailbreak_score": 0,
            "malicious_request_score": 0
        }
        return scores





