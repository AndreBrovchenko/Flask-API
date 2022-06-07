import requests

URL = 'http://127.0.0.1:5000/flask-app/api'

# response = requests.get(f'{URL}/test')
# response = requests.post(f'{URL}/test?qparam1=re1&qparam2=res2',
#                          json={'some_1': 'pass1', 'some_2': 'pass_2'},
#                          headers={'token': 'vsgsrdrgdresygsteg'}
#                          )
# ------------------------------
# Это сработало !
# response = requests.post(f'{URL}/user/',
#                          json={'user_name': 'user_2', 'email': 'email_user_2', 'password': '123_araa443dffFFd'},
#                          headers={'token': 'vsgsrdrgdresygsteg'},
#                          )

# это сработало и создавался каждый раз новый токен даже для имеющихся пользователей
# response = requests.post(f'{URL}/login/',
#                          json={'user_name': 'user_1', 'email': 'email_user_1', 'password': '123_araa443dffFFd'},
#                          )

response = requests.post(f'{URL}/login/',
                         json={'user_name': 'user_1', 'email': 'email_user_1', 'password': '123_araa443dffFFd'},
                         )
token = response.json()['token']
print(token)
response = requests.get(f'{URL}/user/1/',
                        json={'user_name': 'user_1', 'email': 'email_user_1', 'password': '123_araa443dffFFd'},
                        headers={'token': token},
                        )
# {'message': 'invalid token'}
# response = requests.get(f'{URL}/user/1/',
#                         json={'user_name': 'user_1', 'email': 'email_user_1', 'password': '123_araa443dffFFd'},)

# {'message': 'invalid token'}
# response = requests.get(f'{URL}/user/1/')
# response = requests.post(f'{URL}/advert/',
#                          json={'title': 'title_advert_1', 'description': 'description_t_a_1', 'owner': 1},
#                          )
# response = requests.post(f'{URL}/advert/',
#                          json={'title': 'title_advert_1', 'description': 'description_t_a_1', 'owner': '1'},
#                          )
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
