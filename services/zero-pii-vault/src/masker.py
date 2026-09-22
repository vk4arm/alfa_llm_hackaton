"""
Zero-PII Vault: Natasha-powered Neural & Algorithmic Masker
Compliant with Russian Federal Laws: 152-FZ (Personal Data) & 395-1 (Banking Secrecy).

Supported entities:
1.  ФИО (Full Name, declension & inflections handled via Slovnet/Natasha PER NER with intent grounding)
2.  Дата рождения (Birth Date)
3.  Место рождения (Place of Birth)
4.  Серия и номер паспорта РФ (Passport Series & Number)
5.  Гражданство (Citizenship)
6.  Орган, выдавший паспорт (Issuing Authority)
7.  Код подразделения (Department Code)
8.  Дата выдачи паспорта (Passport Issue Date)
9.  Серия и номер водительского удостоверения (Driver's License)
10. Адрес (Country, postal code, city, street, house, apartment)
11. Email
12. Номер телефона (Russian mobile & landline phones)
13. ИНН (10-digit legal & 12-digit individual with FNS checksum validation)
14. Номер банковской карты (16 digits with Luhn algorithm validation)
15. CVV / CVC код карты (Security code)
16. Пин-код карты (PIN code)
17. Имя держателя карты (Cardholder name)
"""

import re
import uuid
from typing import Dict, Tuple, List, Optional, Set
from natasha import (
    Segmenter,
    MorphVocab,
    NewsEmbedding,
    NewsNERTagger,
    AddrExtractor,
    Doc
)

def luhn_checksum_valid(card_number_str: str) -> bool:
    """Validates 13-19 digit card number using Luhn algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled if doubled < 10 else doubled - 9
        else:
            checksum += digit
    return checksum % 10 == 0

def validate_inn(inn: str) -> bool:
    """Validates Russian Tax Identification Number (ИНН) with official check digits."""
    digits = [int(c) for c in inn if c.isdigit()]
    if len(digits) == 10:
        weights = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(w * d for w, d in zip(weights, digits[:9])) % 11 % 10
        return checksum == digits[9]
    elif len(digits) == 12:
        weights1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum1 = sum(w * d for w, d in zip(weights1, digits[:10])) % 11 % 10
        weights2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum2 = sum(w * d for w, d in zip(weights2, digits[:11])) % 11 % 10
        return checksum1 == digits[10] and checksum2 == digits[11]
    return False

# Whitelist of renowned poets, writers, artists, scientists, philosophers, and historical personalities
FAMOUS_PERSON_BASES: Set[str] = {
    # 1. Русская литература, поэзия и публицистика
    "пушкин", "лермонтов", "толст", "достоевск", "чехов", "гогол", "тургенев", "бунин", "куприн", "горьк",
    "некрасов", "тютчев", "фет", "крылов", "жуковск", "карамзин", "грибоедов", "фонвизин", "радищев", "чаадаев",
    "белинск", "герцен", "чернышевск", "добролюбов", "писарев", "маяковск", "есенин", "ахматов", "цветаев",
    "бродск", "блок", "мандельштам", "пастернак", "набоков", "булгаков", "солженицын", "замятин", "платонов",
    "шаламов", "шолохов", "бабель", "ильф", "петров", "зощенко", "хармс", "высоцк", "окуджав", "рождественск",
    "вознесенск", "евтушенко", "ахмадулин", "твардовск", "симонов", "маршак", "чуковск", "барто", "михалков",
    "берггольц", "волошин", "сологуб", "бальмонт", "гиппиус", "мережковск", "гумилев", "ходасевич", "северянин",
    "рубцов", "вампилов", "распутин", "астафьев", "шукшин", "трифонов", "довлатов", "сорокин", "пелевин",
    "стругацк", "улицк", "водолазкин", "пришвин", "бианки", "бажов", "паустовск", "каверин", "катаев",
    # 2. Зарубежная литература, поэзия и драматургия
    "гомер", "вергили", "овидий", "данте", "петрарк", "боккаччо", "чосер", "шекспир", "мольер", "сервантес",
    "рабле", "вольтер", "руссо", "дидро", "гете", "гёте", "шиллер", "байрон", "шелли", "китс", "вордсворт",
    "колридж", "гейне", "гофман", "бальзак", "стендаль", "флобер", "золя", "гюго", "дюма", "верн", "мопассан",
    "пруст", "бодлер", "верлен", "рембо", "селин", "сартр", "камю", "беккет", "ионеско", "диккенс", "тэккерей",
    "остин", "бронте", "уайльд", "шоу", "киплинг", "конрад", "вульф", "джойс", "оруэлл", "хаксли", "твен",
    "мелвилл", "уитмен", "лондон", "хэмингуэй", "хемингуэй", "фолкнер", "фицджеральд", "стейнбек", "сэлинджер",
    "брэдбери", "азимов", "воннегут", "буковски", "керуак", "кинг", "кафка", "кафк", "рильке", "манн", "ремарк",
    "гессе", "цвейг", "брехт", "борхес", "маркес", "кортасар", "льоса", "неруда", "памук", "мураками", "мисима",
    "акутагава", "эко", "кальвино", "по", "эдгар по", "дойл", "конан дойл", "агата кристи",
    # 3. Философия, социология, психология и общественная мысль
    "сократ", "платон", "аристотель", "пифагор", "гераклит", "демокрит", "эпикур", "зенон", "цицерон", "сенека",
    "марк аврелий", "плотин", "августин", "аквинск", "макиавелли", "монтень", "бэкон", "бекон", "гоббс", "декарт",
    "спиноз", "лейбниц", "локк", "беркли", "юм", "кант", "фихте", "шеллинг", "гегел", "фейербах", "шопенгауэр",
    "кьеркегор", "ницш", "маркс", "энгельс", "ленин", "вебер", "дюркгейм", "франкл", "фрейд", "юнг", "адлер",
    "фромм", "гуссерль", "хайдеггер", "ясперс", "витгенштейн", "рассел", "поппер", "кун", "фуко", "деррида",
    "делез", "бодрийяр", "хабермас", "жижек", "конфуци", "лао-цзы", "чжуан-цзы", "сунь-цзы", "будд",
    # 4. Естественные науки, физика, математика, химия, биология, космонавтика
    "ньютон", "галилей", "коперник", "кеплер", "архимед", "эвклид", "евклид", "ферма", "паскаль", "эйлер", "гаусс",
    "лаплас", "лагранж", "коши", "риман", "пуанкаре", "гильберт", "гедель", "тьюринг", "лобачевск", "чебышев",
    "ковалевск", "колмогоров", "марков", "ляпунов", "перельман", "франклин", "кулон", "вольта", "ампер", "ом",
    "фарадей", "максвелл", "герц", "рентген", "томсон", "резерфорд", "планк", "эйнштейн", "гейзенберг", "шредингер",
    "дирак", "ферми", "фейнман", "ландау", "сахаров", "капиц", "тамм", "басов", "прохоров", "алферов", "кюри",
    "хокинг", "пенроуз", "ломоносов", "менделеев", "лавуазье", "дальтон", "авогадро", "бутлеров", "курчатов",
    "дарвин", "ламарк", "линней", "мендель", "павлов", "сеченов", "мечников", "пастер", "кох", "флеминг",
    "вавилов", "вернадск", "тимирязев", "морган", "крик", "уотсон", "маркони", "белл", "эдисон", "тесла", "тесл",
    "попов", "циолковск", "королев", "глушко", "гагарин", "титов", "леонов", "терешков", "армстронг",
    # 5. IT, компьютерные науки и технологические визионеры
    "шеннон", "фон нейман", "нейман", "винер", "дейкстра", "кнут", "торвальдс", "бернерс-ли", "возняк",
    "джобс", "гейтс", "маск", "альтман", "цукерберг", "безос", "кармак", "пейдж", "брин", "пичаи", "кук",
    # 6. Музыка и композиторы
    "бах", "гендель", "вивальди", "гайдн", "моцарт", "бетховен", "шуберт", "шуман", "мендельсон", "шопен",
    "лист", "вагнер", "верди", "брамс", "бизе", "пуччини", "россини", "доницетти", "малер", "штраус",
    "дебюсси", "равель", "сен-санс", "паганини", "глинка", "даргомыжск", "мусоргск", "бородин", "римский-корсаков",
    "балакирев", "чайковск", "рахманинов", "скрябин", "стравинск", "прокофьев", "шостакович", "хачатурян",
    "свиридов", "шнитке",
    # 7. Живопись, скульптура и архитектура
    "джотто", "боттичелли", "леонардо", "микеланджело", "рафаэл", "тициан", "караваджо", "бернини", "рембрандт",
    "вермеер", "рубенс", "веласкес", "гойя", "тернер", "констебль", "моне", "ренуар", "дега", "сезанн",
    "гоген", "ван гог", "мунк", "климт", "шиле", "пикассо", "матисс", "дали", "магритт", "шагал", "модильяни",
    "кандинск", "малевич", "татлин", "родченко", "рублев", "дионисий", "брюллов", "айвазовск", "репин",
    "суриков", "шишкин", "саврасов", "левитан", "куинджи", "васнецов", "поленов", "врубель", "серов",
    "коровин", "кустодиев", "рерих",
    # 8. Исторические деятели, полководцы и лидеры эпох
    "цезар", "цицерон", "спартак", "македонск", "ганнибал", "перикл", "клеопатр", "наполеон", "бонапарт",
    "вашингтон", "линкольн", "черчилль", "рузвельт", "де голль", "бисмарк", "гарибальди", "суворов",
    "кутузов", "ушаков", "нахимов", "жуков", "рокоссовск"
}

FAMOUS_PERSONS: Set[str] = {
    # Russian Classic Literature & Poetry
    "пушкин", "пушкина", "пушкину", "пушкиным", "пушкине",
    "есенин", "есенина", "есенину", "есениным", "есенине",
    "лермонтов", "лермонтова", "лермонтову", "лермонтовым", "лермонтове",
    "толстой", "толстого", "толстому", "толстым", "толстом",
    "достоевский", "достоевского", "достоевскому", "достоевским", "достоевском",
    "чехов", "чехова", "чехову", "чеховым", "чехове",
    "маяковский", "маяковского", "маяковскому", "маяковским", "маяковском",
    "блок", "блока", "блоку", "блоком", "блоке",
    "ахматова", "ахматовой", "ахматову", "цветаева", "цветаевой", "цветаеву",
    "булгаков", "булгакова", "булгакову", "булгаковым", "булгакове",
    "гоголь", "гоголя", "гоголю", "гоголем", "гоголе",
    "тургенев", "тургенева", "тургеневу", "тургеневым", "тургеневе",
    "пастернак", "пастернака", "пастернаку", "пастернаком", "пастернаке",
    "бродский", "бродского", "бродскому", "бродским", "бродском",
    "мандельштам", "мандельштама", "мандельштаму", "мандельштамом", "мандельштаме",
    "некрасов", "некрасова", "некрасову", "некрасовым", "некрасове",
    "тютчев", "тютчева", "тютчеву", "тютчевым", "тютчеве",
    "фет", "фета", "фету", "фетом", "фете",
    "крылов", "крылова", "крылову", "крыловым", "крылове",
    "грибоедов", "грибоедова", "грибоедову", "грибоедовым", "грибоедове",
    "куприн", "куприна", "куприну", "куприным", "куприне",
    "бунин", "бунина", "бунину", "буниным", "бунине",
    "набоков", "набокова", "набокову", "набоковым", "набокове",
    "горький", "горького", "горькому", "горьким", "горьком",
    "высоцкий", "высоцкого", "высоцкому", "высоцким", "высоцком",
    "окуджава", "окуджавы", "окуджаве", "окуджаву",
    "стругацкий", "стругацкие", "стругацких", "стругацким",
    # Science, Thought & Heritage
    "ломоносов", "ломоносова", "ломоносову", "ломоносовым", "ломоносове",
    "менделеев", "менделеева", "менделееву", "менделеевым", "менделееве",
    "чайковский", "чайковского", "чайковскому", "чайковским", "чайковском",
    "рахманинов", "рахманинова", "рахманинову", "рахманиновым", "рахманинове",
    "гагарин", "гагарина", "гагарину", "гагариным", "гагарине",
    "королев", "королева", "королеву", "королевым", "королеве",
    "циолковский", "циолковского", "циолковскому", "циолковским", "циолковском",
    "ньютон", "ньютона", "эйнштейн", "эйнштейна", "шекспир", "шекспира",
    "байрон", "байрона", "гёте", "гете", "моцарт", "моцарта", "бах", "баха",
    "бетховен", "бетховена", "сократ", "сократа", "платон", "платона",
    "аристотель", "аристотеля", "леонардо", "дарвин", "дарвина", "тесла", "теслу",
    "ницше", "кант", "канта", "канту", "шопен", "шопена", "шопену",
    "фейнман", "фейнмана", "фейнману", "хокинг", "хокинга", "тьюринг", "тьюринга",
    "джобс", "джобса", "джобсом", "маск", "маска", "маском", "гейтс", "гейтса"
}

# Imperative action verbs and dialog stopwords that must never be treated as client names
VERB_STOPWORDS: Set[str] = {
    "отправь", "отправить", "отправьте", "переведи", "перевести", "переведите",
    "перекинь", "перекинуть", "перекиньте", "скинь", "скинуть", "скиньте",
    "закинь", "закинуть", "закиньте", "перебрось", "перебросить",
    "пополни", "пополнить", "пополните", "заблокируй", "заблокировать", "заблокируйте",
    "разблокируй", "разблокировать", "разблокируйте", "позвони", "позвонить", "позвоните",
    "напиши", "написать", "напишите", "ответь", "ответить", "ответьте",
    "рассуждай", "рассуждать", "рассуждайте", "слушай", "слушайте",
    "проанализируй", "подскажи", "найди", "сделай", "помоги", "оформи",
    "здравствуйте", "привет", "добрый", "внимание", "сообщение", "запрос",
    "клиент", "заемщик", "заявитель", "плательщик", "получатель", "бенефициар"
}

class NatashaPIIMasker:
    """
    High-speed, lightweight PII anonymizer and reversible tokenizer.
    Combines rule-based validators (Luhn, FNS checksums, RFC regexes) with
    Natasha (Slovnet compact embeddings + Yargy grammars) for morphological NER,
    with intent-grounding and cultural figure exclusion.
    """
    def __init__(self, granular_address: bool = False):
        self.granular_address = granular_address
        self.famous_persons = FAMOUS_PERSONS
        self.famous_person_bases = FAMOUS_PERSON_BASES
        self.verb_stopwords = VERB_STOPWORDS
        
        # Initialize lightweight NLP engines
        self.segmenter = Segmenter()
        self.morph_vocab = MorphVocab()
        self.emb = NewsEmbedding()
        self.ner_tagger = NewsNERTagger(self.emb)
        self.addr_extractor = AddrExtractor(self.morph_vocab)
        
        # Stylistic, comparative, and roleplay triggers (e.g. "Ты, как Пушкин", "в стиле Есенина")
        self.metaphor_pattern = re.compile(
            r'(?i)\b(?:ты,?\s+как|как|как\s+если\s+бы|будто|словно|представь,?\s+что\s+ты|'
            r'в\s+стиле|в\s+манере|в\s+духе|словами|стихи|поэзи[яие]|стихотворени[яе]|произведени[яе]|'
            r'творчеств[ое]|биографи[яи]|автор[а-я]*|писател[а-я]*|поэт[а-я]*|кто\s+такой|книг[а-я]*|'
            r'роман[а-я]*|повест[а-я]*|цитат[а-я]*|философи[яие]|теори[яие]|симфони[яие]|картин[а-я]*|'
            r'по\s+заветам|по\s+рецепту|рассуждай|ответь|напиши)\b'
        )

        # Banking, transactional, and identity intent triggers anywhere in proximity
        self.banking_intent_pattern = re.compile(
            r'(?i)\b(?:'
            # Transaction & payment verbs
            r'перевести|переведи|переведите|перевод[а-я]*|'
            r'перекинь[а-я]*|перебрось[а-я]*|скинь[а-я]*|закинь[а-я]*|'
            r'отправить|отправь|отправьте|отправление|'
            r'перечислить|перечисли|перечислите|перечисление|'
            r'пополнить|пополни|пополните|пополнение|'
            r'списать|спиши|списание|оплатить|оплати|оплата|'
            r'выплатить|выплати|выплата|выдать|выдай|'
            # Banking instruments, accounts & destinations
            r'счет[а-я]*|карточк[а-я]*|карт[а-я]*|пластик[а-я]*|'
            r'телефон[а-я]*|сотов[а-я]*|номер[а-я]*|'
            r'рубл[а-я]*|руб|деньг[а-я]*|средств[а-я]*|сумм[а-я]*|платеж[а-я]*|'
            r'депозит[а-я]*|вклад[а-я]*|кредит[а-я]*|ипотек[а-я]*|заем[а-я]*|займ[а-я]*|'
            # Identity, roles & relations
            r'клиент[а-я]*|заявител[а-я]*|заемщик[а-я]*|плательщик[а-я]*|получател[а-я]*|бенефициар[а-я]*|владелец[а-я]*|'
            r'от\s+клиента|от\s+кого|фио|на\s+имя|в\s+пользу|от\s+имени|'
            r'заблокировать|заблокируй|разблокировать|разблокируй|выписк[а-я]*|анкет[а-я]*|договор[а-я]*|'
            r'я,|зовут|ее\s+зовут|его\s+зовут|гражданин[а-я]*|гражданк[а-я]*|обратил[а-я]*|'
            r'паспорт[а-я]*|инн|свв|cvv|пин|pin|'
            r'брат[а-я]*|сестр[а-я]*|друг[а-я]*|коллег[а-я]*'
            r')\b'
        )
        
        # Explicit customer identity regex pattern (strictly requiring capitalized Name words)
        self.identity_person_pattern = re.compile(
            r'(?:(?i:\b(?:клиент[а-я]*|заявител[а-я]*|заемщик[а-я]*|плательщик[а-я]*|получател[а-я]*|бенефициар[а-я]*|фио|я|меня\s+зовут|зовут|ее\s+зовут|его\s+зовут|гражданин[а-я]*|гражданк[а-я]*|обратил(?:ся|ась)|пользовател[а-я]*|владелец|от|с\s+уважением,?)\b)\s*[:\-–—]?\s*)([A-ZА-ЯЁ][a-zа-яё]+(?:\s+[A-ZА-ЯЁ][a-zа-яё]+){1,2})'
        )

        # 1. Financial & Account Identifiers (supports spaces, dashes, dots, slashes, underscores, tildes, brackets, mixed)
        self.card_pattern = re.compile(r'(?<!\d)(?:\d[- \t._/~–—]*){12,18}\d(?!\d)')
        self.inn_pattern = re.compile(
            r'(?i)(?:\bИНН(?:/[А-ЯЁA-Z0-9]+)?\b\s*[:\-–—]?\s*)?((?<!\d)\d{1,6}(?:[- \t._/~–—]+\d{1,6}){1,6}(?!\d)|\b\d{10}\b|\b\d{12}\b)'
        )
        self.cvv_pattern = re.compile(
            r'(?i)(?:\b(?:cvv2?|cvc2?|cid|код\s+безопасности|код\s+на\s+обороте|свв|цвв|'
            r'(?:последние\s+)?три\s+цифр[ыок]+(?:\s+сзади|\s+на\s+обороте)?|'
            r'(?:последние\s+)?(?:три\s+)?циферк[иек]+(?:\s+сзади|\s+на\s+обороте)?|'
            r'код\s+сзади)\b[^\d\n]{0,25}?(?:были?|равен|указан)?[:\-–—\s]*?)(\d{3,4})\b'
        )
        self.pin_pattern = re.compile(
            r'(?i)(?:\b(?:пин(?:-?код)?|pin(?:-?code)?|пароль(?:\s+от\s+карты)?)\b[^\d\n]{0,20}?(?:был|стоял|установлен|равен)?[:\-–—\s]*?)(\d{4})(?=[)\]\s,.;\n]|$)'
        )
        self.cardholder_pattern = re.compile(
            r'(?i)(?:\b(?:держатель(?:\s+карты)?|cardholder(?:\s+name)?|card\s*holder|'
            r'(?:имя\s+)?(?:на\s+карте|на\s+пластике)(?:\s+(?:указано|написано|выбито|стоит))?|'
            r'карто?ч?ка\s+на\s+имя|на\s+имя\s+держателя)\b\s*[:\-–—]?\s*)'
            r'([A-Z\s]{3,35}|[А-ЯЁ\s]{3,35})(?=[,\n\.;\)]|$)'
        )
        
        # 2. Government IDs & Documents
        self.vu_pattern = re.compile(
            r'(?i)(?:\b(?:водительск[а-я\s]*(?:удостоверени[а-я]*|прав[а-я]*)|прав[а-я]*|в/?у)\b[^\d\n]{0,35}?(?:сери[яи]\s*)?)'
            r'([0-9]{2}\s?[0-9А-ЯA-Z]{2}\s*(?:№|номер\s*)?[0-9]{6})\b'
        )
        self.pass_code_pattern = re.compile(
            r'(?i)\b(?:код(?:\s+на\s+штампе|\s+подразделени[яе]|\s+выдачи|\s+отделения|\s+органа)?|подразделени[ея]|отделени[а-я]*|к/?п)\b[^\d\n]{0,15}?(\b\d{3}[-\s]\d{3}\b)'
        )
        self.pass_pattern = re.compile(
            r'(?i)(?:'
            r'\b(?:паспорт(?:[а-я\s]*РФ|[а-я]*ные\s+данные|[а-я]*)?|по\s+паспорту|в\s+паспорте|сери[яи]\s+и\s+номер|данные\s+документа|реквизиты\s+паспорта|мой\s+паспорт)\b[^\d\n]{0,35}?(?:сери[яи]\s*)?(\b\d{2}\s?\d{2}\b)\s*(?:№|номер|n\.)?\s*(\b\d{6}\b)|'
            r'\bсери[яи]\s*(\b\d{2}\s?\d{2}\b)\s*(?:№|номер|n\.)?\s*(\b\d{6}\b)'
            r')'
        )
        self.issuer_pattern = re.compile(
            r'(?i)(?:\b(?:кем\s+выдан|орган[,\s]+выдавший[^\n,;]*|орган\s+выдачи|выдан[а-я]*|получал[а-я]*|оформлял[а-я]*|выдали)\b[^\n,;:]{0,25}?(?:его\s+|в\s+|через\s+)?[:\-–—]?\s*)'
            r'([^\n,;\(\)]+?(?:отдел[а-я]*|уфмс|мвд|овд|ровд|гу\s+мвд|умвд|тп\s+№|отделени[а-я]*|паспортн[а-я]*)[^\n,;\(\)]*?)'
            r'(?=\s+\d{2}[./]\d{2}[./]\d{4}|\s*\(|\s*,|\s*;|\s*\n|$)'
        )
        self.pass_date_pattern = re.compile(
            r'(?i)(?:'
            r'(?:\b(?:дата\s+выдачи(?:\s+паспорта)?|выдан[а-я]*(?:\s+паспорт)?(?:\s+от)?|получен[а-я]*|оформлен[а-я]*|получал[а-я]*|оформлял[а-я]*)\b[^\d\n]{0,120}?)(\d{2}[./]\d{2}[./]\d{4})|'
            r'(\d{2}[./]\d{2}[./]\d{4})\s*(?:года\s+)?(?:\b(?:выдачи|получения|оформления)\b)'
            r')'
        )
        self.citizen_pattern = re.compile(
            r'(?i)(?:\b(?:гражданств[оа-я]*|гражданин[а-я]*|гражданк[а-я]*|подданств[оа-я]*)\b[^\n,;:]{0,15}?(?:я\s+)?[:\-–—]?\s*)(РФ|Российская Федерация|Росси[яие]|Республика\s+[А-Яа-яЁё]+|[А-Яа-яЁё\-]{3,20})\b'
        )
        
        # 3. Biographic & Personal Data
        self.birth_date_pattern = re.compile(
            r'(?i)(?:'
            r'(?:\b(?:дата(?:\s+и\s+место)?\s+рождения|д\.?р\.?|родил(?:ся|ась)|г\.?р\.?|рождени[яе]|появил(?:ся|ась)\s+на\s+свет|моего\s+рождения)\b[^\d\n]{0,25}?)(\d{2}[./]\d{2}[./]\d{4})|'
            r'(\d{2}[./]\d{2}[./]\d{4})\s*(?:г\.?\s*р\.?|год[а-я]*\s+рождени[яе])'
            r')'
        )
        self.birth_place_pattern = re.compile(
            r'(?i)(?:'
            r'\b(?:родил(?:ся|ась)|появил(?:ся|ась)\s+на\s+свет|урожен(?:ец|ка)|родом)\b[^\n,;]{0,45}?\b(?:в|из)\s+(?:городе\s+|гор\.\s*|г\.\s*)?([А-ЯЁ][а-яё\-]+)|'
            r'\b(?:место\s+рождени[яе]|урожен(?:ец|ка))\s*[:\-–—]?\s*(?:городе\s+|гор\.\s*|г\.\s*)?([А-ЯЁ][а-яё\-]+)'
            r')'
        )
        
        # 4. Contacts & Location (handles dots, slashes, underscores, tildes, unicode dashes, 007, and glued prefixes)
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
        self.phone_pattern = re.compile(
            r'(?:(?i:\b(?:тел(?:\.|ефон)?|моб(?:\.|ильный)?|т\.|номер(?:\s+для\s+связи)?|сотовом[уе]?|сотовый)\s*[:\-–—]?\s*))?'
            r'(?P<num>'
            r'(?<!\d)(?:(?:\+?7|8|007)[\s\.\-_/–—~]*)?(?:[\(\[]\s*\d{3,4}\s*[\)\]]|(?<!\d)\d{3,4})[\s\.\-_/–—~]*\d{2,3}[\s\.\-_/–—~]*\d{2}[\s\.\-_/–—~]*\d{2}(?!\d)|'
            r'(?<!\d)(?:(?:\+?7|8|007)[\s\.\-_/–—~]*)?(?:[\(\[]\s*\d{3,4}\s*[\)\]]|(?<!\d)\d{3,4})[\s\.\-_/–—~]*\d{7}(?!\d)|'
            r'(?<!\d)(?:\+?7|8)\d{10}(?!\d)|'
            r'(?<!\d)(?:[\(\[]\s*\d{3,4}\s*[\)\]]|(?<!\d)9\d{2})[\s\.\-_/–—~]*\d{2,3}[\s\.\-_/–—~]*\d{2}[\s\.\-_/–—~]*\d{2}(?!\d)'
            r')'
        )
        self.address_line_pattern = re.compile(
            r'(?i)(?:\b(?:адрес(?:[а-я\s]*регистрации|[а-я\s]*проживания)?|'
            r'зарегистрирован[а-я\s]*|прожива[а-я]*|прописан[а-я]*|жив[а-я]*|доставк[а-я]*)\b[^\n]{0,35}?(?:по\s+адресу\s+|в\s+|на\s+адрес\s+|на\s+)?[:\-–—]?\s*)'
            r'((?:г\.|гор\.|город\s+|Россия|[0-9]{6},|[А-ЯЁ][а-яё\-]+|[A-ZА-ЯЁ]{2,5})[^\n;]+?(?:ул\.|улиц[а-я]*|наб\.|пр-?к?т|просп[а-я]*|пер\.|переулок|шоссе|ш\.|бул\.|бульвар|д\.|дом|Арбат)[^\n]+?[0-9]+(?:[,\s]+(?:кв\.|квартир[а-я]*|корп\.|к\.|оф\.|строени[ея]|стр\.)\s*[0-9]+)*)(?=[,\.;\n\)]|\s+хотя|\s+но|\s+паспорт|$)'
        )

    def is_person_pii(self, raw_name: str, full_text: str, start: int, end: int) -> bool:
        """
        Determines whether a detected person name is genuine personal data (PII)
        tied to client identity or banking intents, or a cultural/stylistic reference.
        """
        # Clean trailing prepositions or particles if attached by NER
        clean_name = re.sub(r'\s+\b(?:по|в|на|и|с|о|от|к|для|при|из|под|за)\b\s*$', '', raw_name.strip(" ,.:;!?()\"'"))
        words = clean_name.split()
        if not words:
            return False

        clean_lower = clean_name.lower()
        if clean_lower in self.verb_stopwords:
            return False

        # Context window preceding and following the detected name (bidirectional)
        prefix = full_text[max(0, start - 80):start]
        suffix = full_text[end:min(len(full_text), end + 80)]

        # 1. Metaphor, comparative, roleplay or literary context check restricted to the current sentence/clause prefix
        line_prefix = prefix.split('\n')[-1]
        clause_prefix = re.split(r'[\.\?!;,\(\)]\s*', line_prefix)[-1]
        has_metaphor = bool(self.metaphor_pattern.search(clause_prefix))

        # 2. Check if name matches a famous cultural/historical personality or public figure
        words_lower = [w.lower().strip(" ,.:;!?") for w in words]
        is_famous = any(
            any(w.startswith(b) for b in self.famous_person_bases) or w in self.famous_persons
            for w in words_lower
        )

        # 3. Check if accompanied by a banking/transaction intent or identity label in proximity
        has_banking_intent = bool(
            self.banking_intent_pattern.search(prefix) or self.banking_intent_pattern.search(suffix)
        )

        if is_famous:
            # Famous personality is ONLY masked if explicitly bound to a banking/transaction intent:
            # e.g. "Клиент: Маяковский В.В.", "Перевести 5000 рублей Пушкину на карту...", "Скинь Ницше 500 руб"
            # and is NOT part of a metaphor/roleplay prompt ("Ты, как Пушкин", "в стиле Есенина")
            if has_banking_intent and not has_metaphor:
                return True
            return False

        # 4. For ordinary names:
        if has_metaphor:
            return False

        # Single capitalized word without banking intent is rejected to avoid false positives (e.g. "Позвони", "Тикет")
        if len(words) < 2 and not has_banking_intent:
            return False

        return True

    def mask(self, text: str, session_id: Optional[str] = None) -> Tuple[str, str, Dict[str, str]]:
        """
        Masks all identified PII entities, returning:
        (sanitized_text, session_id, mapping_dict)
        """
        if not session_id:
            session_id = str(uuid.uuid4())
            
        spans: List[Tuple[int, int, str, str]] = [] # (start, end, label, raw_text)
        
        def is_overlapping(start: int, end: int) -> bool:
            return any(not (end <= s or start >= e) for s, e, _, _ in spans)
            
        def add_span(start: int, end: int, label: str, val: str):
            if not is_overlapping(start, end):
                spans.append((start, end, label, val))

        # 1. Driver's License
        for m in self.vu_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'DRIVER_LICENSE', m.group(1))

        # 2. Bank Cards (Luhn validated, supports spaces, dashes, dots, slashes, underscores, tildes, brackets, mixed)
        for m in self.card_pattern.finditer(text):
            raw = m.group(0)
            cleaned = re.sub(r'\D', '', raw)
            if (13 <= len(cleaned) <= 19) and luhn_checksum_valid(cleaned):
                add_span(m.start(), m.end(), 'CARD', raw)

        # 3. INN (Checksum validated, supports spaces, dashes, dots, slashes, underscores, tildes, brackets)
        for m in self.inn_pattern.finditer(text):
            raw = m.group(1) if m.group(1) else m.group(0)
            clean = re.sub(r'\D', '', raw)
            if len(clean) in (10, 12) and validate_inn(clean):
                st = m.start(1) if m.group(1) else m.start(0)
                en = m.end(1) if m.group(1) else m.end(0)
                add_span(st, en, 'INN', raw)

        # 4. Passport code
        for m in self.pass_code_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PASSPORT_CODE', m.group(1))

        # 5. Passport series & number
        for m in self.pass_pattern.finditer(text):
            add_span(m.start(), m.end(), 'PASSPORT', m.group(0))

        # 6. Email
        for m in self.email_pattern.finditer(text):
            add_span(m.start(), m.end(), 'EMAIL', m.group(0))

        # 7. Phone (supports all diverse formats: dots, slashes, underscores, tildes, brackets, solid digits, 007, glued prefixes)
        for m in self.phone_pattern.finditer(text):
            raw = m.group('num') if m.group('num') else m.group(0)
            clean = re.sub(r'\D', '', raw)
            if len(clean) in (10, 11) or (clean.startswith('007') and len(clean) == 13):
                st = m.start('num') if m.group('num') else m.start(0)
                en = m.end('num') if m.group('num') else m.end(0)
                add_span(st, en, 'PHONE', raw)

        # 8. CVV
        for m in self.cvv_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CVV', m.group(1))

        # 9. PIN
        for m in self.pin_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PIN', m.group(1))

        # 10. Cardholder
        for m in self.cardholder_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CARDHOLDER', m.group(1).strip())

        # 11. Birth date (prefix or suffix triggers)
        for m in self.birth_date_pattern.finditer(text):
            val = m.group(1) or m.group(2)
            st = m.start(1) if m.group(1) else m.start(2)
            en = m.end(1) if m.group(1) else m.end(2)
            add_span(st, en, 'BIRTHDATE', val)

        # 12. Passport issue date
        for m in self.pass_date_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'PASSPORT_DATE', m.group(1))

        # 13. Birth place (conversational: "родился в Самаре", "уроженец г. Казань", "родом из ...")
        for m in self.birth_place_pattern.finditer(text):
            val = (m.group(1) or m.group(2)).strip()
            st = m.start(1) if m.group(1) else m.start(2)
            en = m.end(1) if m.group(1) else m.end(2)
            add_span(st, en, 'BIRTHPLACE', val)

        # 14. Citizenship
        for m in self.citizen_pattern.finditer(text):
            add_span(m.start(1), m.end(1), 'CITIZENSHIP', m.group(1).strip())

        # 15. Passport issuer (handles conversational "паспорт получал в ...", "выдан через ...")
        for m in self.issuer_pattern.finditer(text):
            raw_val = m.group(1).strip()
            clean_val = re.sub(r'^(?:его\s+|в\s+|через\s+)+', '', raw_val)
            st = m.start(1) + (len(raw_val) - len(clean_val))
            en = m.end(1)
            add_span(st, en, 'PASSPORT_ISSUER', clean_val)

        # 16. Address (Full line or granular breakdown, handles conversational "живу в Москве на Тверской...")
        if not self.granular_address:
            for m in self.address_line_pattern.finditer(text):
                raw_val = m.group(1).strip()
                clean_val = re.sub(r'^(?:сейчас\s+|по\s+адресу\s+|в\s+|на\s+адрес\s+|на\s+)+', '', raw_val)
                clean_val = re.sub(r'(?:,\s*(?:хотя|паспорт|прописан|тел|но|к/п|код|выдан).*)$', '', clean_val)
                st = m.start(1) + (len(raw_val) - len(clean_val))
                en = st + len(clean_val)
                add_span(st, en, 'ADDRESS', clean_val)
        else:
            for m in self.addr_extractor(text):
                t_label = m.fact.type or 'addr_part'
                tag = {
                    'страна': 'COUNTRY',
                    'индекс': 'POSTCODE',
                    'город': 'CITY',
                    'улица': 'STREET',
                    'дом': 'HOUSE',
                    'квартира': 'FLAT'
                }.get(t_label, 'ADDRESS_PART')
                add_span(m.start, m.stop, tag, text[m.start:m.stop])

        # 17. Explicit customer identity pattern (Forms, applications, claims)
        for m in self.identity_person_pattern.finditer(text):
            val = m.group(1).strip()
            if self.is_person_pii(val, text, m.start(1), m.end(1)):
                add_span(m.start(1), m.end(1), 'FIO', val)

        # 18. Natasha NER for ФИО (PER) with Intent & Cultural-figure filtering and span merging
        doc = Doc(text)
        doc.segment(self.segmenter)
        doc.tag_ner(self.ner_tagger)
        per_spans = [s for s in doc.spans if s.type == 'PER']
        merged_spans: List[Tuple[int, int, str]] = []
        for s in per_spans:
            if merged_spans and merged_spans[-1][1] <= s.start and text[merged_spans[-1][1]:s.start].strip() == '':
                prev_st, prev_en, prev_text = merged_spans.pop()
                merged_spans.append((prev_st, s.stop, text[prev_st:s.stop]))
            else:
                merged_spans.append((s.start, s.stop, s.text))

        for st, en, raw_name in merged_spans:
            raw_name = raw_name.strip()
            # Strip leading prefix if bound to intro particle
            if raw_name.startswith('Я, '):
                raw_name = raw_name[3:].strip()
                st += 3
            
            # Strip leading command/action verb if glued by NER (e.g. "Скинь Ницше", "Переведи Маяковскому")
            first_word = raw_name.split()[0].rstrip(',:').lower()
            if first_word in self.verb_stopwords and len(raw_name.split()) > 1:
                v_len = len(raw_name.split()[0])
                rest = raw_name[v_len:].lstrip(' ,:')
                st += len(raw_name) - len(rest)
                raw_name = rest

            # Clean trailing preposition if attached by NER
            cleaned_name = re.sub(r'\s+\b(?:по|в|на|и|с|о|от|к|для|при|из|под|за)\b\s*$', '', raw_name)
            if len(cleaned_name) < len(raw_name):
                en = st + len(cleaned_name)
                raw_name = cleaned_name

            # Apply intent-aware & cultural figure filtering
            if self.is_person_pii(raw_name, text, st, en):
                add_span(st, en, 'FIO', raw_name)

        # Sort spans by start position ascending
        spans.sort(key=lambda x: x[0])
        
        # Build substitution and mapping
        mapping: Dict[str, str] = {}
        counters: Dict[str, int] = {}
        
        # Replace from end to start to preserve index offsets
        result_chars = list(text)
        for start, end, label, _ in reversed(spans):
            counters[label] = counters.get(label, 0) + 1
            token = f"[{label}_{counters[label]}]"
            mapping[token] = text[start:end]
            result_chars[start:end] = list(token)
            
        masked_text = "".join(result_chars)
        return masked_text, session_id, mapping

    def unmask(self, masked_text: str, mapping: Dict[str, str]) -> str:
        """
        Reverses tokenization using the ephemeral session mapping.
        """
        result = masked_text
        for token, original_value in mapping.items():
            result = result.replace(token, original_value)
        return result
