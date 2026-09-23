#!/usr/bin/env python3
"""
Test dataset builder for PII / Bank Secrecy masking benchmarks.
Populates realistic Russian banking dialogues, loan applications, KYC tickets, and claims
containing:
- Full names (ФИО)
- Dates of birth (Дата рождения)
- Places of birth (Место рождения)
- Passport series & numbers (Серия и номер паспорта)
- Citizenship (Гражданство)
- Passport issuing authorities (Орган, выдавший паспорт)
- Department codes (Код подразделения)
- Passport issue dates (Дата выдачи паспорта)
- Driver's license numbers (В/У)
- Full addresses (Country, postal code, city, street, house, apartment)
- Email addresses
- Phone numbers
- INN with valid FNS checksums (10 & 12 digits)
- Bank cards with valid Luhn checksums
- CVV/CVC codes
- PIN codes
- Cardholder names
"""

import os
import random

FIRST_NAMES_MALE = [
    "Александр", "Дмитрий", "Максим", "Сергей", "Андрей", "Алексей", "Артем", "Илья",
    "Кирилл", "Михаил", "Никита", "Матвей", "Роман", "Егор", "Арсений", "Иван",
    "Денис", "Евгений", "Даниил", "Тимофей", "Владислав", "Игорь", "Владимир", "Павел"
]

LAST_NAMES_MALE = [
    "Иванов", "Смирнов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов", "Михайлов",
    "Новиков", "Федоров", "Морозов", "Волков", "Алексеев", "Лебедев", "Семенов", "Егоров",
    "Павлов", "Козлов", "Степанов", "Николаев", "Орлов", "Андреев", "Макаров", "Никитин"
]

PATRONYMICS_MALE = [
    "Александрович", "Дмитриевич", "Сергеевич", "Андреевич", "Алексеевич", "Игоревич",
    "Владимирович", "Михайлович", "Иванович", "Николаевич", "Павлович", "Романович"
]

FIRST_NAMES_FEMALE = [
    "Анна", "Мария", "Елена", "Дарья", "Алина", "Полина", "Екатерина", "Виктория",
    "Анастасия", "Ольга", "Татьяна", "Наталья", "Ксения", "Светлана", "Юлия", "Ирина"
]

LAST_NAMES_FEMALE = [
    "Иванова", "Смирнова", "Кузнецова", "Попова", "Васильева", "Петрова", "Соколова",
    "Михайлова", "Новикова", "Федорова", "Морозова", "Волкова", "Алексеева", "Лебедева"
]

PATRONYMICS_FEMALE = [
    "Александровна", "Дмитриевна", "Сергеевна", "Андреевна", "Алексеевна", "Игоревна",
    "Владимировна", "Михайловна", "Ивановна", "Николаевна", "Павловна", "Романовна"
]

CITIES = [
    ("г. Москва", "101000", "77"),
    ("г. Санкт-Петербург", "190000", "78"),
    ("г. Новосибирск", "630000", "54"),
    ("г. Екатеринбург", "620000", "66"),
    ("г. Казань", "420000", "16"),
    ("г. Нижний Новгород", "603000", "52"),
    ("г. Самара", "443000", "63"),
    ("г. Ростов-на-Дону", "344000", "61"),
    ("г. Уфа", "450000", "02"),
    ("г. Красноярск", "660000", "24"),
    ("г. Воронеж", "394000", "36"),
    ("г. Пермь", "614000", "59"),
    ("г. Волгоград", "400000", "34"),
    ("г. Краснодар", "350000", "23"),
    ("г. Саратов", "410000", "64")
]

STREETS = [
    "ул. Ленина", "просп. Мира", "ул. Тверская", "ул. Советская", "ул. Гагарина",
    "ул. Кирова", "просп. Ленина", "ул. Пушкина", "ул. Садовая", "наб. Реки Мойки",
    "ул. Арбат", "просп. Победы", "ул. Красная", "ул. Баумана", "ул. Малышева"
]

ISSUERS = [
    "Отделом УФМС России по гор. Москве в районе Замоскворечье",
    "ТП № 1 Отдела УФМС России по Санкт-Петербургу и Ленинградской обл.",
    "Отделом МВД России по Пресненскому району города Москвы",
    "ГУ МВД России по Свердловской области",
    "Отделом УФМС России по Республике Татарстан в Вахитовском районе",
    "Межрайонным отделом УФМС России по Самарской области в г. Самаре",
    "Отделением УФМС России по Новосибирской области в Центральном районе",
    "УМВД России по городу Краснодару",
    "Отделом МВД России по Нижегородскому району г. Нижнего Новгорода"
]

CITIZENSHIPS = [
    "РФ", "Российская Федерация", "Россия", "Республика Беларусь", "Республика Казахстан"
]

DOMAINS = ["yandex.ru", "mail.ru", "gmail.com", "rambler.ru", "bk.ru", "inbox.ru", "corp-bank.ru"]

def cyr_to_translit(text: str) -> str:
    table = {
        'а':'a','б':'b','в':'v','г':'g','д':'d','е':'e','ё':'e',
        'ж':'zh','з':'z','и':'i','й':'y','к':'k','л':'l','м':'m',
        'н':'n','о':'o','п':'p','р':'r','с':'s','т':'t','у':'u',
        'ф':'f','х':'kh','ц':'ts','ч':'ch','ш':'sh','щ':'shch',
        'ъ':'','ы':'y','ь':'','э':'e','ю':'yu','я':'ya'
    }
    res = []
    for c in text.lower():
        res.append(table.get(c, c))
    return "".join(res)

def make_valid_inn10() -> str:
    d = [random.randint(1, 9)] + [random.randint(0, 9) for _ in range(8)]
    w = [2, 4, 10, 3, 5, 9, 4, 6, 8]
    c = sum(wi * di for wi, di in zip(w, d)) % 11 % 10
    d.append(c)
    return "".join(map(str, d))

def make_valid_inn12() -> str:
    d = [random.randint(1, 9)] + [random.randint(0, 9) for _ in range(9)]
    w1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    c1 = sum(wi * di for wi, di in zip(w1, d)) % 11 % 10
    d.append(c1)
    w2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    c2 = sum(wi * di for wi, di in zip(w2, d)) % 11 % 10
    d.append(c2)
    return "".join(map(str, d))

def make_valid_card(bin_prefix: str = "4276") -> str:
    digits = [int(c) for c in bin_prefix] + [random.randint(0, 9) for _ in range(15 - len(bin_prefix))]
    s = 0
    for i, d in enumerate(digits[::-1]):
        if i % 2 == 0:
            doubled = d * 2
            s += doubled if doubled < 10 else doubled - 9
        else:
            s += d
    check_digit = (10 - (s % 10)) % 10
    digits.append(check_digit)
    return "".join(map(str, digits))

def random_person():
    is_male = random.random() < 0.5
    if is_male:
        first = random.choice(FIRST_NAMES_MALE)
        last = random.choice(LAST_NAMES_MALE)
        patr = random.choice(PATRONYMICS_MALE)
    else:
        first = random.choice(FIRST_NAMES_FEMALE)
        last = random.choice(LAST_NAMES_FEMALE)
        patr = random.choice(PATRONYMICS_FEMALE)
    
    full_name = f"{last} {first} {patr}"
    cardholder = f"{cyr_to_translit(first).upper()} {cyr_to_translit(last).upper()}"
    
    b_day = random.randint(1, 28)
    b_month = random.randint(1, 12)
    b_year = random.randint(1965, 2004)
    birth_date = f"{b_day:02d}.{b_month:02d}.{b_year}"
    
    city_item = random.choice(CITIES)
    city_name, postal_code, region_code = city_item
    birth_place = f"{city_name}"
    
    pass_year = min(b_year + random.randint(14, 25), 2024) % 100
    pass_series = f"{region_code}{pass_year:02d}"
    pass_num = f"{random.randint(100000, 999999)}"
    
    p_day = random.randint(1, 28)
    p_month = random.randint(1, 12)
    p_year = 2000 + pass_year if pass_year < 50 else 1900 + pass_year
    pass_date = f"{p_day:02d}.{p_month:02d}.{p_year}"
    
    dept_code = f"{region_code}{random.randint(0, 9)}-{random.randint(100, 999)}"
    issuer = random.choice(ISSUERS)
    citizenship = random.choice(CITIZENSHIPS)
    
    vu_series = f"{region_code} {random.randint(10, 99)}"
    vu_num = f"{random.randint(100000, 999999)}"
    driver_license = f"{vu_series} {vu_num}"
    
    street = random.choice(STREETS)
    house_num = random.randint(1, 150)
    flat_num = random.randint(1, 280)
    address_str = f"Россия, {postal_code}, {city_name}, {street}, д. {house_num}, кв. {flat_num}"
    
    login = f"{cyr_to_translit(first)[0]}.{cyr_to_translit(last)}"
    email = f"{login}{random.randint(10, 99)}@{random.choice(DOMAINS)}"
    
    phone_prefix = random.choice(["903", "916", "925", "926", "985", "905", "911", "921"])
    phone = f"+7 ({phone_prefix}) {random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(10, 99)}"
    
    inn = make_valid_inn12() if random.random() < 0.7 else make_valid_inn10()
    
    bin_p = random.choice(["4276", "5469", "2200", "4154"])
    card = make_valid_card(bin_p)
    cvv = f"{random.randint(100, 999)}"
    pin = f"{random.randint(1000, 9999)}"
    
    return {
        "fio": full_name,
        "first": first,
        "last": last,
        "cardholder": cardholder,
        "birth_date": birth_date,
        "birth_place": birth_place,
        "pass_series": pass_series,
        "pass_num": pass_num,
        "pass_date": pass_date,
        "issuer": issuer,
        "dept_code": dept_code,
        "citizenship": citizenship,
        "driver_license": driver_license,
        "postal_code": postal_code,
        "city": city_name,
        "street": street,
        "house": f"д. {house_num}",
        "flat": f"кв. {flat_num}",
        "address": address_str,
        "email": email,
        "phone": phone,
        "inn": inn,
        "card": card,
        "cvv": cvv,
        "pin": pin
    }

TEMPLATES = [
    # 1. Заявка на кредит
    """Заявка на кредитование №{req_id}
Заявитель: {fio}
Дата рождения: {birth_date}, место рождения: {birth_place}
Гражданство: {citizenship}
Паспортные данные: серия {pass_series} номер {pass_num}
Кем выдан: {issuer}
Дата выдачи: {pass_date}, код подразделения: {dept_code}
Водительское удостоверение: {driver_license}
Адрес постоянной регистрации: {address}
Контактные данные: телефон {phone}, адрес эл. почты {email}
ИНН заемщика: {inn}
Для зачисления кредитных средств указана банковская карта {card}, держатель: {cardholder}.
Код безопасности CVV: {cvv}, резервный пин-код: {pin}.
Прошу рассмотреть возможность выдачи кредита в размере {amount} рублей на срок 36 месяцев.""",

    # 2. Обращение в службу безопасности / саппорт
    """Тикет в службу поддержки банка #{req_id}
От клиента: {fio}
Тема: Блокировка операций по карте и обновление персональных данных
Я, {fio}, дата рождения {birth_date} (место рождения {birth_place}), гражданин: {citizenship}.
Сообщаю о компрометации карты {card} (на карте указано имя {cardholder}).
С подозрением столкнулся после запроса cvv {cvv} на фишинговом сайте.
Мой пин-код {pin} не передавался третьим лицам.
Для идентификации подтверждаю реквизиты паспорта: {pass_series} {pass_num}, выдан {pass_date}, подразделение {dept_code}, орган выдачи: {issuer}.
Мой действующий ИНН: {inn}, серия и номер в/у: {driver_license}.
Актуальный адрес проживания: {address}.
Прошу связаться со мной по номеру {phone} или написать на почту {email}.""",

    # 3. Заявление на чарджбэк / мошеннические действия
    """Претензионное заявление о несогласии с транзакцией #{req_id}
В претензионный отдел от: {fio}
Паспорт РФ: серия {pass_series} № {pass_num}, выдан {issuer}, дата выдачи {pass_date}, код {dept_code}.
Дата и место рождения заявителя: {birth_date}, {birth_place}. Гражданство: {citizenship}.
Зарегистрирован по адресу: {address} (почтовый индекс {postal_code}).
Номер мобильного телефона для связи: {phone}, e-mail: {email}.
Идентификационный номер налогоплательщика (ИНН): {inn}.
Оспариваемая операция совершена по карте {card} (держатель {cardholder}, указан CVV {cvv}).
Пин-код карты ({pin}) никому не сообщался. Прошу вернуть списанную сумму {amount} руб.""",

    # 4. Анкета открытия счета ИП / юрлица
    """Анкета комплексного банковского обслуживания клиента #{req_id}
1. Сведения о клиенте:
ФИО: {fio}
Дата рождения: {birth_date}, место рождения: {birth_place}
Гражданство: {citizenship}
ИНН: {inn}
Документ, удостоверяющий личность: Паспорт РФ серия {pass_series} номер {pass_num}
Орган, выдавший документ: {issuer}
Дата выдачи паспорта: {pass_date}, код подразделения: {dept_code}
Дополнительный документ (водительское удостоверение): {driver_license}
Адрес регистрации: {address}
2. Контактная информация:
Телефон: {phone}
E-mail: {email}
3. Корпоративная бизнес-карта:
Номер карты: {card}, держатель: {cardholder}
Код CVV: {cvv}, первоначальный пин-код: {pin}."""
]

EDGE_CHUNKS = [
    "доп документы: загран 51-1234567, паспорт беларуси мс-1234567, св-во о рожд. vi ав123456.",
    "клиент предоставил даркон 12345678 и узбекский паспорт ac12345678.",
    "в базе числится военник вг1234567 и теудат-зехут: 123456789.",
    "Свидетельство на ребенка: X-ЕР№123456. У брата казахский паспорт 123456789.",
    "загранпаспорт: 511234567, лессе пассе 12345678, паспорт снг 123456789.",
    "опечатки: белорусский паспорт МС1234567, военный билет ВГ-1234567, паспорт рб мс1234567."
]

def create_record(req_id: int) -> str:
    p = random_person()
    tmpl = random.choice(TEMPLATES)
    amount = f"{random.randint(50, 950) * 1000:,}".replace(",", " ")
    return tmpl.format(req_id=req_id, amount=amount, **p)

def build_dataset_to_size(target_bytes: int, filename: str):
    records = []
    current_bytes = 0
    req_id = 10001
    
    while current_bytes < target_bytes:
        rec = create_record(req_id) + "\n\n" + ("=" * 80) + "\n\n"
        rec_bytes = len(rec.encode("utf-8"))
        records.append(rec)
        current_bytes += rec_bytes
        req_id += 1
    
    content = "".join(records)
    # Trim or ensure reasonable fit near target
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
        
    actual_size = os.path.getsize(filename)
    print(f"Created {filename}: {actual_size} bytes ({actual_size / 1024:.2f} KB, {actual_size / (1024*1024):.2f} MB), {req_id - 10001} records")

if __name__ == "__main__":
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "pii_samples"))
    os.makedirs(out_dir, exist_ok=True)
    
    # 15 KB, 100 KB, 2 MB
    build_dataset_to_size(15 * 1024, os.path.join(out_dir, "pii_dataset_15kb.txt"))
    build_dataset_to_size(100 * 1024, os.path.join(out_dir, "pii_dataset_100kb.txt"))
    build_dataset_to_size(2 * 1024 * 1024, os.path.join(out_dir, "pii_dataset_2mb.txt"))
