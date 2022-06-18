import requests

URL = 'http://127.0.0.1:5000/flask-app/api'


def test():
    return requests.get(f'{URL}/test')


def test2():
    return requests.post(f'{URL}/test?qparam1=re1&qparam2=res2',
                         json={'some_1': 'pass1', 'some_2': 'pass_2'},
                         headers={'token': 'vsgsrdrgdresygsteg'}
                         )


def create_new_user():
    return requests.post(f'{URL}/user/',
                         json={'user_name': 'user_3', 'email': 'email_user_3', 'password': '123_araa443dffFFd'},
                         )


def registration_user():
    return requests.post(f'{URL}/login/',
                         json={'user_name': 'user_1', 'email': 'email_user_1', 'password': '123_araa443dffFFd'},
                         )


def receive_user():
    response = requests.post(f'{URL}/login/',
                             json={'user_name': 'user_1', 'password': '123_araa443dffFFd'},)
    if response.status_code == 200:
        user_name = response.json()['user_name']
        user_token = response.json()['token']
        user_id = response.json()['user_id']
        print(response.json())
        return requests.get(f'{URL}/user/{user_id}/',
                            headers={'user_name': user_name, 'token': user_token},)


def create_advert():
    response = requests.post(f'{URL}/login/',
                             json={'user_name': 'user_2', 'password': '123_araa443dffFFd'},
                             )
    if response.status_code == 200:
        user_name = response.json()['user_name']
        user_token = response.json()['token']
        user_id = response.json()['user_id']
        return requests.post(f'{URL}/advert/',
                             headers={'user_name': user_name, 'token': user_token},
                             json={'title': 'title_advert_2', 'description': 'description_t_a_2'},
                             )


def receive_advert():
    return requests.get(f'{URL}/advert/1/')


def edit_advert():
    response = requests.post(f'{URL}/login/',
                             json={'user_name': 'user_1', 'password': '123_araa443dffFFd'},
                             )
    if response.status_code == 200:
        user_name = response.json()['user_name']
        user_token = response.json()['token']
        user_id = response.json()['user_id']
        return requests.put(f'{URL}/advert/1/',
                            headers={'user_name': user_name, 'token': user_token},
                            json={'title': 'title_advert_1=', 'description': 'description_t_a_1='},
                            )


def delete_advert():
    response = requests.post(f'{URL}/login/',
                             json={'user_name': 'user_2', 'password': '123_araa443dffFFd'},
                             )
    if response.status_code == 200:
        user_name = response.json()['user_name']
        user_token = response.json()['token']
        user_id = response.json()['user_id']
        return requests.delete(f'{URL}/advert/12/',
                               headers={'user_name': user_name, 'token': user_token},
                               )


def report(response):
    print(response.status_code)
    print(response.json())
    # print(response.text)


# test()
# report(test2())
# report(create_new_user())
# report(registration_user())
# report(receive_user())
# report(create_advert())
report(receive_advert())
# report(edit_advert())
# report(delete_advert())
