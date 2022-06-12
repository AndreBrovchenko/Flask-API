import requests

URL = 'http://127.0.0.1:5000/flask-app/api'

# -- Тестовые запросы
# response = requests.get(f'{URL}/test')
# response = requests.post(f'{URL}/test?qparam1=re1&qparam2=res2',
#                          json={'some_1': 'pass1', 'some_2': 'pass_2'},
#                          headers={'token': 'vsgsrdrgdresygsteg'}
#                          )
# ++++++++++++++++++
# -- Создание нового пользователя.
# response = requests.post(f'{URL}/user/',
#                          json={'user_name': 'user_2', 'email': 'email_user_2', 'password': '123_araa443dffFFd'},
#                          )
# ++++++++++++++++++
# -- Регистрация пользователя.
# -- При каждой регистрации, создается новый токен даже для имеющихся пользователей
# response = requests.post(f'{URL}/login/',
#                          json={'user_name': 'user_1', 'email': 'email_user_1', 'password': '123_araa443dffFFd'},
#                          )
# ++++++++++++++++++
# -- Получение данных о пользователе.
# -- Сначала делается запрос POST для получения токена.
# -- Потом с этим токеном выполняем запрос GET
# response = requests.post(f'{URL}/login/',
#                          json={'user_name': 'user_1', 'password': '123_araa443dffFFd'},
#                          )
# user_name = response.json()['user_name']
# user_token = response.json()['token']
# user_id = response.json()['user_id']
# print(response.json())
# response = requests.get(f'{URL}/user/{user_id}/',
#                         headers={'user_name': user_name, 'token': user_token},
#                         )
# ++++++++++++++++++
# Удалить
# {'message': 'invalid token'}
# response = requests.get(f'{URL}/user/1/',
#                         json={'user_name': 'user_1', 'email': 'email_user_1', 'password': '123_araa443dffFFd'},)
# Удалить
# {'message': 'invalid token'}
# response = requests.get(f'{URL}/user/1/')
# Удалить
# {'message': 'invalid token'}
# response = requests.get(f'{URL}/user/1/',
#                         headers={'user_name': 'user_1'},
#                         )
# ++++++++++++++++++
# -- Создание объявления
# response = requests.post(f'{URL}/login/',
#                          json={'user_name': 'user_2', 'password': '123_araa443dffFFd'},
#                          )
# user_name = response.json()['user_name']
# user_token = response.json()['token']
# user_id = response.json()['user_id']
# response = requests.post(f'{URL}/advert/',
#                          headers={'user_name': user_name, 'token': user_token},
#                          json={'title': 'title_advert_4', 'description': 'description_t_a_4', 'owner': user_id},
#                          )
# ++++++++++++++++++
# -- Редактирование объявления
response = requests.post(f'{URL}/login/',
                         json={'user_name': 'user_1', 'password': '123_araa443dffFFd'},
                         )
user_name = response.json()['user_name']
user_token = response.json()['token']
user_id = response.json()['user_id']
response = requests.put(f'{URL}/advert/4/',
                        headers={'user_name': user_name, 'token': user_token},
                        json={'title': 'title_advert_3', 'description': 'description_t_a_3', 'owner': user_id},
                        )
# ++++++++++++++++++
# -- Получение объявления
# response = requests.get(f'{URL}/advert/4/')
# ++++++++++++++++++


# ------------------------------ дальше все удалить
# response = requests.post(f'{URL}/user/',
#                          json={'user_name': 'user_1', 'email': 'email_user_1', 'password': 'pass_1'},
#                          headers={'token': 'abracadabra_1_ABRACADABRA+1234'}
#                          )
# response = requests.post(f'{URL}/user?user_name=user_1&qparam2=res2')
# response = requests.post(f'{URL}/user')

print(response.status_code)
print(response.json())
# print(response.text)
