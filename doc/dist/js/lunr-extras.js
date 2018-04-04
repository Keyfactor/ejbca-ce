
String.prototype.replaceAt=function(index, character) {
    return this.substr(0, index) + character + this.substr(index+character.length);
};

lunr.wordTrimmer = function(token){
    return token.substr(0,50);
};

lunr.Pipeline.registerFunction(lunr.wordTrimmer, 'wordTrimmer');

lunr.stopWordFilterGerman = function (token) {
    if (lunr.stopWordFilterGerman.stopWords.indexOf(token) === -1) return token
};

lunr.stopWordFilterGerman.stopWords = new lunr.SortedSet;
lunr.stopWordFilterGerman.stopWords.length = 352;
lunr.stopWordFilterGerman.stopWords.elements = [
 "ab",
 "aber",
 "abgesehen",
 "alle",
 "allein",
 "aller",
 "alles",
 "als",
 "am",
 "an",
 "andere",
 "anderen",
 "anderenfalls",
 "anderer",
 "anderes",
 "anstatt",
 "auch",
 "auf",
 "aus",
 "aussen",
 "außen",
 "ausser",
 "außer",
 "ausserdem",
 "außerdem",
 "außerhalb",
 "ausserhalb",
 "behalten",
 "bei",
 "beide",
 "beiden",
 "beider",
 "beides",
 "beinahe",
 "bevor",
 "bin",
 "bis",
 "bist",
 "bitte",
 "da",
 "daher",
 "danach",
 "dann",
 "darueber",
 "darüber",
 "darueberhinaus",
 "darüberhinaus",
 "darum",
 "das",
 "dass",
 "daß",
 "dem",
 "den",
 "der",
 "des",
 "deshalb",
 "die",
 "diese",
 "diesem",
 "diesen",
 "dieser",
 "dieses",
 "dort",
 "duerfte",
 "duerften",
 "duerftest",
 "duerftet",
 "dürfte",
 "dürften",
 "dürftest",
 "dürftet",
 "durch",
 "durfte",
 "durften",
 "durftest",
 "durftet",
 "ein",
 "eine",
 "einem",
 "einen",
 "einer",
 "eines",
 "einige",
 "einiger",
 "einiges",
 "entgegen",
 "entweder",
 "erscheinen",
 "es",
 "etwas",
 "fast",
 "fertig",
 "fort",
 "fuer",
 "für",
 "gegen",
 "gegenueber",
 "gegenüber",
 "gehalten",
 "geht",
 "gemacht",
 "gemaess",
 "gemäß",
 "genug",
 "getan",
 "getrennt",
 "gewesen",
 "gruendlich",
 "gründlich",
 "habe",
 "haben",
 "habt",
 "haeufig",
 "häufig",
 "hast",
 "hat",
 "hatte",
 "hatten",
 "hattest",
 "hattet",
 "hier",
 "hindurch",
 "hintendran",
 "hinter",
 "hinunter",
 "ich",
 "ihm",
 "ihnen",
 "ihr",
 "ihre",
 "ihrem",
 "ihren",
 "ihrer",
 "ihres",
 "ihrige",
 "ihrigen",
 "ihriges",
 "immer",
 "in",
 "indem",
 "innerhalb",
 "innerlich",
 "irgendetwas",
 "irgendwelche",
 "irgendwenn",
 "irgendwo",
 "irgendwohin",
 "ist",
 "jede",
 "jedem",
 "jeden",
 "jeder",
 "jedes",
 "jedoch",
 "jemals",
 "jemand",
 "jemandem",
 "jemanden",
 "jemandes",
 "jene",
 "jung",
 "junge",
 "jungem",
 "jungen",
 "junger",
 "junges",
 "kann",
 "kannst",
 "kaum",
 "koennen",
 "koennt",
 "koennte",
 "koennten",
 "koenntest",
 "koenntet",
 "können",
 "könnt",
 "könnte",
 "könnten",
 "könntest",
 "könntet",
 "konnte",
 "konnten",
 "konntest",
 "konntet",
 "machen",
 "macht",
 "machte",
 "mehr",
 "mehrere",
 "mein",
 "meine",
 "meinem",
 "meinen",
 "meiner",
 "meines",
 "meistens",
 "mich",
 "mir",
 "mit",
 "muessen",
 "müssen",
 "muesst",
 "müßt",
 "muß",
 "muss",
 "musst",
 "mußt",
 "nach",
 "nachdem",
 "naechste",
 "nächste",
 "nebenan",
 "nein",
 "nichts",
 "niemand",
 "niemandem",
 "niemanden",
 "niemandes",
 "nirgendwo",
 "nur",
 "oben",
 "obwohl",
 "oder",
 "oft",
 "ohne",
 "pro",
 "sagte",
 "sagten",
 "sagtest",
 "sagtet",
 "scheinen",
 "sehr",
 "sei",
 "seid",
 "seien",
 "seiest",
 "seiet",
 "sein",
 "seine",
 "seinem",
 "seinen",
 "seiner",
 "seines",
 "seit",
 "selbst",
 "sich",
 "sie",
 "sind",
 "so",
 "sogar",
 "solche",
 "solchem",
 "solchen",
 "solcher",
 "solches",
 "sollte",
 "sollten",
 "solltest",
 "solltet",
 "sondern",
 "statt",
 "stets",
 "tatsächlich",
 "tatsaechlich",
 "tief",
 "tun",
 "tut",
 "ueber",
 "über",
 "ueberall",
 "überall",
 "um",
 "und",
 "uns",
 "unser",
 "unsere",
 "unserem",
 "unseren",
 "unserer",
 "unseres",
 "unten",
 "unter",
 "unterhalb",
 "usw",
 "viel",
 "viele",
 "vielleicht",
 "von",
 "vor",
 "vorbei",
 "vorher",
 "vorueber",
 "vorüber",
 "waehrend",
 "während",
 "wann",
 "war",
 "waren",
 "warst",
 "wart",
 "was",
 "weder",
 "wegen",
 "weil",
 "weit",
 "weiter",
 "weitere",
 "weiterem",
 "weiteren",
 "weiterer",
 "weiteres",
 "welche",
 "welchem",
 "welchen",
 "welcher",
 "welches",
 "wem",
 "wen",
 "wenige",
 "wenn",
 "wer",
 "werde",
 "werden",
 "werdet",
 "wessen",
 "wie",
 "wieder",
 "wir",
 "wird",
 "wirklich",
 "wirst",
 "wo",
 "wohin",
 "wuerde",
 "wuerden",
 "wuerdest",
 "wuerdet",
 "würde",
 "würden",
 "würdest",
 "würdet",
 "wurde",
 "wurden",
 "wurdest",
 "wurdet",
 "ziemlich",
 "zu",
 "zum",
 "zur",
 "zusammen",
 "zwischen" ];
 
lunr.Pipeline.registerFunction(lunr.stopWordFilterGerman, 'stopWordFilterGerman');

lunr.stemmerGerman = (function(word){
	var len;

	len = word.length - 1;

    word = word.replace(/ä/gi, "a");
    word = word.replace(/à/gi, "a");
    word = word.replace(/á/gi, "a");
    word = word.replace(/â/gi, "a");

    word = word.replace(/è/gi, "e");
    word = word.replace(/é/gi, "e");
    word = word.replace(/ê/gi, "e");

    word = word.replace(/ï/gi, "i");
    word = word.replace(/ì/gi, "i");
    word = word.replace(/í/gi, "i");
    word = word.replace(/î/gi, "i");

    word = word.replace(/ö/gi, "o");
    word = word.replace(/ò/gi, "o");
    word = word.replace(/ó/gi, "o");
    word = word.replace(/ô/gi, "o");

    word = word.replace(/ü/gi, "u");
    word = word.replace(/ù/gi, "u");
    word = word.replace(/ú/gi, "u");
    word = word.replace(/û/gi, "u");

    word = word.replace(/ç/gi, "c");
    word = word.replace(/ñ/gi, "n");

	if (len > 5) {
        if ((word[len] == 'n') && (word[len - 1] == 'e') && (word[len - 2] == 'n')) {
            word = word.slice(0, len - 2);
            /*  ending with -nen  */
        }
    }
    if (len > 4) {
        if (word[len]=='n' && word[len-1]=='r' && word[len-2]=='e') {
            word = word.slice(0, len - 2);  /*  ending with -ern ->   */
        }
		 if (word[len]=='t' && word[len-1]=='s' && word[len-2]=='e') {
            word = word.slice(0, len - 2);  /*  ending with -est ->   */
        }
    }
    if (len > 3) {
        if (word[len]=='m' && word[len-1]=='e') {
            word = word.slice(0, len - 1);  /*  ending with -em ->  */
        }
        if (word[len]=='n' && word[len-1]=='e') {
            word = word.slice(0, len - 1);  /*  ending with -en ->  */
        }
        if (word[len]=='r' && word[len-1]=='e') {
            word = word.slice(0, len - 1);  /*  ending with -er ->  */
        }
        if (word[len]=='s' && word[len-1]=='e') {
            word = word.slice(0, len - 1); /*  ending with -es ->  */
        }
		 if (word[len]=='r' && word[len-1]=='e') {
            word = word.slice(0, len - 1);  /*  ending with -er ->  */
        }
        if (word[len]=='n' && word[len-1]=='e') {
            word = word.slice(0, len - 1);  /*  ending with -en ->  */
        }
        if (word[len]=='t' && word[len-1]=='s') {
            word = word.slice(0, len - 1);  /*  ending with -st ->  */
        }
    }
    if (len > 2) {
        if (word[len]=='e') {
            word = word.slice(0, len);  /*  ending with -e ->  */
        }
    }

	return word;
    
 });

lunr.Pipeline.registerFunction(lunr.stemmerGerman, 'stemmerGerman');

lunr.stopWordFilterFrench = function (token) {
    if (lunr.stopWordFilterFrench.stopWords.indexOf(token) === -1) return token
};

lunr.stopWordFilterFrench.stopWords = new lunr.SortedSet;
lunr.stopWordFilterFrench.stopWords.length = 463;
lunr.stopWordFilterFrench.stopWords.elements = [
"a",
"à",
"â",
"abord",
"afin",
"ah",
"ai",
"aie",
"ainsi",
"allaient",
"allo",
"allô",
"allons",
"après",
"assez",
"attendu",
"au",
"aucun",
"aucune",
"aujourd",
"aujourd'hui",
"auquel",
"aura",
"auront",
"aussi",
"autre",
"autres",
"aux",
"auxquelles",
"auxquels",
"avaient",
"avais",
"avait",
"avant",
"avec",
"avoir",
"ayant",
"b",
"bah",
"beaucoup",
"bien",
"bigre",
"boum",
"bravo",
"brrr",
"c",
"ça",
"car",
"ce",
"ceci",
"cela",
"celle",
"celle-ci",
"celle-là",
"celles",
"celles-ci",
"celles-là",
"celui",
"celui-ci",
"celui-là",
"cent",
"cependant",
"certain",
"certaine",
"certaines",
"certains",
"certes",
"ces",
"cet",
"cette",
"ceux",
"ceux-ci",
"ceux-là",
"chacun",
"chaque",
"cher",
"chère",
"chères",
"chers",
"chez",
"chiche",
"chut",
"ci",
"cinq",
"cinquantaine",
"cinquante",
"cinquantième",
"cinquième",
"clac",
"clic",
"combien",
"comme",
"comment",
"compris",
"concernant",
"contre",
"couic",
"crac",
"d",
"da",
"dans",
"de",
"debout",
"dedans",
"dehors",
"delà",
"depuis",
"derrière",
"des",
"dès",
"désormais",
"desquelles",
"desquels",
"dessous",
"dessus",
"deux",
"deuxième",
"deuxièmement",
"devant",
"devers",
"devra",
"différent",
"différente",
"différentes",
"différents",
"dire",
"divers",
"diverse",
"diverses",
"dix",
"dix-huit",
"dixième",
"dix-neuf",
"dix-sept",
"doit",
"doivent",
"donc",
"dont",
"douze",
"douzième",
"dring",
"du",
"duquel",
"durant",
"e",
"effet",
"eh",
"elle",
"elle-même",
"elles",
"elles-mêmes",
"en",
"encore",
"entre",
"envers",
"environ",
"es",
"ès",
"est",
"et",
"etant",
"étaient",
"étais",
"était",
"étant",
"etc",
"été",
"etre",
"être",
"eu",
"euh",
"eux",
"eux-mêmes",
"excepté",
"f",
"façon",
"fais",
"faisaient",
"faisant",
"fait",
"feront",
"fi",
"flac",
"floc",
"font",
"g",
"gens",
"h",
"ha",
"hé",
"hein",
"hélas",
"hem",
"hep",
"hi",
"ho",
"holà",
"hop",
"hormis",
"hors",
"hou",
"houp",
"hue",
"hui",
"huit",
"huitième",
"hum",
"hurrah",
"i",
"il",
"ils",
"importe",
"j",
"je",
"jusqu",
"jusque",
"k",
"l",
"la",
"là",
"laquelle",
"las",
"le",
"lequel",
"les",
"lès",
"lesquelles",
"lesquels",
"leur",
"leurs",
"longtemps",
"lorsque",
"lui",
"lui-même",
"m",
"ma",
"maint",
"mais",
"malgré",
"me",
"même",
"mêmes",
"merci",
"mes",
"mien",
"mienne",
"miennes",
"miens",
"mille",
"mince",
"moi",
"moi-même",
"moins",
"mon",
"moyennant",
"n",
"na",
"ne",
"néanmoins",
"neuf",
"neuvième",
"ni",
"nombreuses",
"nombreux",
"non",
"nos",
"notre",
"nôtre",
"nôtres",
"nous",
"nous-mêmes",
"nul",
"o",
"o|",
"ô",
"oh",
"ohé",
"olé",
"ollé",
"on",
"ont",
"onze",
"onzième",
"ore",
"ou",
"où",
"ouf",
"ouias",
"oust",
"ouste",
"outre",
"p",
"paf",
"pan",
"par",
"parmi",
"partant",
"particulier",
"particulière",
"particulièrement",
"pas",
"passé",
"pendant",
"personne",
"peu",
"peut",
"peuvent",
"peux",
"pff",
"pfft",
"pfut",
"pif",
"plein",
"plouf",
"plus",
"plusieurs",
"plutôt",
"pouah",
"pour",
"pourquoi",
"premier",
"première",
"premièrement",
"près",
"proche",
"psitt",
"puisque",
"q",
"qu",
"quand",
"quant",
"quanta",
"quant-à-soi",
"quarante",
"quatorze",
"quatre",
"quatre-vingt",
"quatrième",
"quatrièmement",
"que",
"quel",
"quelconque",
"quelle",
"quelles",
"quelque",
"quelques",
"quelquun",
"quels",
"qui",
"quiconque",
"quinze",
"quoi",
"quoique",
"r",
"revoici",
"revoilà",
"rien",
"s",
"sa",
"sacrebleu",
"sans",
"sapristi",
"sauf",
"se",
"seize",
"selon",
"sept",
"septième",
"sera",
"seront",
"ses",
"si",
"sien",
"sienne",
"siennes",
"siens",
"sinon",
"six",
"sixième",
"soi",
"soi-même",
"soit",
"soixante",
"son",
"sont",
"sous",
"stop",
"suis",
"suivant",
"sur",
"surtout",
"t",
"ta",
"tac",
"tant",
"te",
"té",
"tel",
"telle",
"tellement",
"telles",
"tels",
"tenant",
"tes",
"tic",
"tien",
"tienne",
"tiennes",
"tiens",
"toc",
"toi",
"toi-même",
"ton",
"touchant",
"toujours",
"tous",
"tout",
"toute",
"toutes",
"treize",
"trente",
"très",
"trois",
"troisième",
"troisièmement",
"trop",
"tsoin",
"tsouin",
"tu",
"u",
"un",
"une",
"unes",
"uns",
"v",
"va",
"vais",
"vas",
"vé",
"vers",
"via",
"vif",
"vifs",
"vingt",
"vivat",
"vive",
"vives",
"vlan",
"voici",
"voilà",
"vont",
"vos",
"votre",
"vôtre",
"vôtres",
"vous",
"vous-mêmes",
"vu",
"w",
"x",
"y",
"z",
"zut"];

lunr.Pipeline.registerFunction(lunr.stopWordFilterFrench, 'stopWordFilterFrench');

lunr.stemmerFrench = (function(word){
	
	 var len;
	 
	len = word.length - 1;
	
	word = word.replace(/ä/gi, "a");
    word = word.replace(/à/gi, "a");
    word = word.replace(/á/gi, "a");
    word = word.replace(/â/gi, "a");

    word = word.replace(/è/gi, "e");
    word = word.replace(/é/gi, "e");
    word = word.replace(/ê/gi, "e");

    word = word.replace(/ï/gi, "i");
    word = word.replace(/ì/gi, "i");
    word = word.replace(/í/gi, "i");
    word = word.replace(/î/gi, "i");

    word = word.replace(/ö/gi, "o");
    word = word.replace(/ò/gi, "o");
    word = word.replace(/ó/gi, "o");
    word = word.replace(/ô/gi, "o");

    word = word.replace(/ü/gi, "u");
    word = word.replace(/ù/gi, "u");
    word = word.replace(/ú/gi, "u");
    word = word.replace(/û/gi, "u");

    word = word.replace(/ç/gi, "c");
    word = word.replace(/ñ/gi, "n");
	
	var normfrenchword = function(word){
		var len = word.length - 1;

		if (len > 3) {
			if (word[len]=='e' && word[len-1]=='i')
			{word = word.slice(0, len - 1);
			 len = word.length - 2;}
		}

		if (len > 3) {
			if (word[len]=='r')
			{word = word.slice(0, len);len--;}
			if (word[len]=='e')
			{word = word.slice(0, len);len--;}
			if (word[len]=='é')
			{word = word.slice(0, len);len--;}
			if (word[len] == word[len-1])
				word = word.slice(0, len);
		}
		return(word);
	};
	
	    if (len > 4) {
        if (word[len]=='x') {
            if (word[len-1]=='u' && word[len-2]=='a' && word[len-3]!='e') {
                word = word.replaceAt(len-1,'l');  /*  chevaux -> cheval  */
            }                 /*  error :  travaux -> traval but not travail  */
            word = word.slice(0, len);      /*  anneaux -> anneau,  neveux -> neveu  */
            len--;               /*  error :  aulx -> aul but not ail (rare)  */
        }
    }                       /*  error :  yeux -> yeu but not oeil (rare)  */
    if (len > 2) {
        if (word[len]=='x') {
            word = word.slice(0, len);      /*  peaux -> peau,  poux -> pou  */
            len--;               /*  error :  affreux -> affreu */
        }
    }

    if (len > 2 && word[len]=='s') {  /*  remove final --s --> -- */
        word = word.slice(0, len);
        len--;
    }

    if (len > 8) {  /* --issement  -->   --ir */
        if (word[len]=='t'   && word[len-1]=='n' && word[len-2]=='e' &&
            word[len-3]=='m' && word[len-4]=='e' && word[len-5]=='s' &&
            word[len-6]=='s' && word[len-7]=='i') {
            word = word.replaceAt(len-6,'r');       /* investissement --> investir */
            word = word.slice(0, len-5);
            return(normfrenchword(word));
        }
    }

    if (len > 7) {  /* ---issant  -->   ---ir */
        if (word[len]=='t'   && word[len-1]=='n' && word[len-2]=='a' &&
            word[len-3]=='s' && word[len-4]=='s' && word[len-5]=='i') {
            word = word.replaceAt(len-4,'r');     /* assourdissant --> assourdir */
            word = word.slice(0, len-3);
            return(normfrenchword(word));
        }
    }

    if (len > 5) {    /* --ement  -->   --e */
        if (word[len]=='t'   && word[len-1]=='n' && word[len-2]=='e' &&
            word[len-3]=='m' && word[len-4]=='e') {
            word = word.slice(0, len-3);       /* pratiquement --> pratique */
            if (word[len-5]=='v' && word[len-6]=='i') {
                word = word.replaceAt(len-5,'f');     /* administrativement --> administratif */
                word = word.slice(0, len-4);
            }
            return(normfrenchword(word));
        }
    }

    if (len > 10) {    /* ---ficatrice  -->   --fier */
        if (word[len]=='e'   && word[len-1]=='c' && word[len-2]=='i' &&
            word[len-3]=='r' && word[len-4]=='t' && word[len-5]=='a' &&
            word[len-6]=='c' && word[len-7]=='i' && word[len-8]=='f') {
            word = word.replaceAt(len-6,'e');
            word = word.replaceAt(len-5,'r');
            word = word.slice(0, len-4);   /* justificatrice --> justifier */
            return(normfrenchword(word));
        }
    }

    if (len > 9) {    /* ---ficateur -->   --fier */
        if (word[len]=='r'   && word[len-1]=='u' && word[len-2]=='e' &&
            word[len-3]=='t' && word[len-4]=='a' && word[len-5]=='c' &&
            word[len-6]=='i' && word[len-7]=='f') {
            word = word.replaceAt(len-5,'e');
            word = word.replaceAt(len-4,'r');
            word = word.slice(0, len-3);  /* justificateur --> justifier */
            return(normfrenchword(word));
        }
    }

    if (len > 8) {    /* ---catrice  -->   --quer */
        if (word[len]=='e'   && word[len-1]=='c' && word[len-2]=='i' &&
            word[len-3]=='r' && word[len-4]=='t' && word[len-5]=='a' &&
            word[len-6]=='c') {
            word = word.replaceAt(len-6,'q');
            word = word.replaceAt(len-5,'u');
            word = word.replaceAt(len-4,'e');
            word = word.replaceAt(len-3,'r');
            word = word.slice(0, len-2);   /* educatrice--> eduquer */
            return(normfrenchword(word));
        }
    }

    if (len > 7) {    /* ---cateur -->   --quer */
        if (word[len]=='r'   && word[len-1]=='u' && word[len-2]=='e' &&
            word[len-3]=='t' && word[len-4]=='a' && word[len-5]=='c') {
            word = word.replaceAt(len-5,'q');
            word = word.replaceAt(len-4,'u');
            word = word.replaceAt(len-3,'e');
            word = word.replaceAt(len-2,'r');
            word = word.slice(0, len-1);    /* communicateur--> communiquer */
            return(normfrenchword(word));
        }
    }

    if (len > 7) {    /* ---atrice  -->   --er */
        if (word[len]=='e'   && word[len-1]=='c' && word[len-2]=='i' &&
            word[len-3]=='r' && word[len-4]=='t' && word[len-5]=='a') {
            word = word.replaceAt(len-5,'e');
            word = word.replaceAt(len-4,'r');
            word = word.slice(0, len-3);   /* accompagnatrice--> accompagner */
            return(normfrenchword(word));
        }
    }

    if (len > 6) {    /* ---ateur  -->   --er */
        if (word[len]=='r'   && word[len-1]=='u' && word[len-2]=='e' &&
            word[len-3]=='t' && word[len-4]=='a') {
            word = word.replaceAt(len-4,'e');
            word = word.replaceAt(len-3,'r');
            word = word.slice(0, len-2);   /* administrateur--> administrer */
            return(normfrenchword(word));
        }
    }

    if (len > 5) {    /* --trice  -->   --teur */
        if (word[len]=='e'   && word[len-1]=='c' && word[len-2]=='i' &&
            word[len-3]=='r' && word[len-4]=='t') {
            word = word.replaceAt(len-3,'u');
            word = word.replaceAt(len-2,'e');
            word = word.replaceAt(len-1,'r');
            word = word.slice(0, len);   /* matrice --> mateur ? */
            len--;
        }
    }

    if (len > 4) {    /* --ième  -->   -- */
        if (word[len]=='e' && word[len-1]=='m' && word[len-2]=='è' &&
            word[len-3]=='i') {
            word = word.slice(0, len-3);
            return(normfrenchword(word));
        }
    }

    if (len > 6) {    /* ---teuse  -->   ---ter */
        if (word[len]=='e'   && word[len-1]=='s' && word[len-2]=='u' &&
            word[len-3]=='e' && word[len-4]=='t') {
            word = word.replaceAt(len-2,'r');
            word = word.slice(0, len-1);       /* acheteuse --> acheter */
            return(normfrenchword(word));
        }
    }

    if (len > 5) {    /* ---teur  -->   ---ter */
        if (word[len]=='r'   && word[len-1]=='u' && word[len-2]=='e' &&
            word[len-3]=='t') {
            word = word.replaceAt(len-1,'r');
            word = word.slice(0, len);       /* planteur --> planter */
            return(normfrenchword(word));
        }
    }

    if (len > 4) {    /* --euse  -->   --eu- */
        if (word[len]=='e' && word[len-1]=='s' && word[len-2]=='u' &&
            word[len-3]=='e') {
            word = word.slice(0, len-1);       /* poreuse --> poreu-,  plieuse --> plieu- */
            return(normfrenchword(word));
        }
    }

    if (len > 7) {    /* ------ère  -->   ------er */
        if (word[len]=='e' && word[len-1]=='r' && word[len-2]=='è') {
            word = word.replaceAt(len-2,'e');
            word = word.replaceAt(len-1,'r');
            word = word.slice(0, len);  /* bijoutière --> bijoutier,  caissière -> caissier */
            return(normfrenchword(word));
        }
    }

    if (len > 6) {    /* -----ive  -->   -----if */
        if (word[len]=='e' && word[len-1]=='v' && word[len-2]=='i') {
            word = word.replaceAt(len-1,'f');   /* but not convive */
            word = word.slice(0, len);   /* abrasive --> abrasif */
            return(normfrenchword(word));
        }
    }

    if (len > 3) {    /* folle or molle  -->   fou or mou */
        if (word[len]=='e' && word[len-1]=='l' && word[len-2]=='l' &&
            word[len-3]=='o' && (word[len-4]=='f' || word[len-4]=='m')) {
            word = word.replaceAt(len-2,'u');
            word = word.slice(0, len-1);  /* folle --> fou */
            return(normfrenchword(word));
        }
    }

    if (len > 8) {    /* ----nnelle  -->   ----n */
        if (word[len]=='e'   && word[len-1]=='l' && word[len-2]=='l' &&
            word[len-3]=='e' && word[len-4]=='n' && word[len-5]=='n') {
            word = word.slice(0, len-4);  /* personnelle --> person */
            return(normfrenchword(word));
        }
    }

    if (len > 8) {    /* ----nnel  -->   ----n */
        if (word[len]=='l'   && word[len-1]=='e' && word[len-2]=='n' &&
            word[len-3]=='n') {
            word = word.slice(0, len-2);  /* personnel --> person */
            return(normfrenchword(word));
        }
    }

    if (len > 3) {    /* --ète  -->  et */
        if (word[len]=='e' && word[len-1]=='t' && word[len-2]=='è') {
            word = word.replaceAt(len-2,'e');
            word = word.slice(0, len);  /* complète --> complet */
            len--;
        }
    }

    if (len > 7) {    /* -----ique  -->   */
        if (word[len]=='e' && word[len-1]=='u' && word[len-2]=='q' &&
            word[len-3]=='i') {
            word = word.slice(0, len-3);  /* aromatique --> aromat */
            len = len-4;
        }
    }

    if (len > 7) {    /* -----esse -->    */
        if (word[len]=='e' && word[len-1]=='s' && word[len-2]=='s' &&
            word[len-3]=='e') {
            word = word.slice(0, len-2);    /* faiblesse --> faible */
            return(normfrenchword(word));
        }
    }

    if (len > 6) {    /* ---inage -->    */
        if (word[len]=='e' && word[len-1]=='g' && word[len-2]=='a' &&
            word[len-3]=='n' && word[len-4]=='i') {
            word = word.slice(0, len-2);  /* patinage --> patin */
            return(normfrenchword(word));
        }
    }

    if (len > 8) {    /* ---isation -->   - */
        if (word[len]=='n'   && word[len-1]=='o' && word[len-2]=='i' &&
            word[len-3]=='t' && word[len-4]=='a' && word[len-5]=='s' &&
            word[len-6]=='i') {
            word = word.slice(0, len-2);     /* sonorisation --> sonor */
            if (len > 11 && word[len-7]=='l' && word[len-8]=='a' && word[len-9]=='u')
                word = word.replaceAt(len-8,'e');  /* ritualisation --> rituel */
            return(normfrenchword(word));
        }
    }

    if (len > 8) {    /* ---isateur -->   - */
        if (word[len]=='r'   && word[len-1]=='u' && word[len-2]=='e' && word[len-3]=='t' &&
            word[len-4]=='a' && word[len-5]=='s' && word[len-6]=='i') {
            word = word.slice(0, len-6);   /* colonisateur --> colon */
            return(normfrenchword(word));
        }
    }

    if (len > 7) {    /* ----ation -->   - */
        if (word[len]=='n'   && word[len-1]=='o' && word[len-2]=='i' &&
            word[len-3]=='t' && word[len-4]=='a') {
            word = word.slice(0, len-4);  /* nomination --> nomin */
            return(normfrenchword(word));
        }
    }

    if (len > 7) {    /* ----ition -->   - */
        if (word[len]=='n'   && word[len-1]=='o' && word[len-2]=='i' &&
            word[len-3]=='t' && word[len-4]=='i') {
            word = word.slice(0, len-4);  /* disposition --> dispos */
            return(normfrenchword(word));
        }
    }
    return(normfrenchword(word));
	
 });

lunr.Pipeline.registerFunction(lunr.stemmerFrench, 'stemmerFrench');

lunr.stopWordFilterSpanish = function (token) {
    if (lunr.stopWordFilterSpanish.stopWords.indexOf(token) === -1) return token
};

lunr.stopWordFilterSpanish.stopWords = new lunr.SortedSet;
lunr.stopWordFilterSpanish.stopWords.length = 307;
lunr.stopWordFilterSpanish.stopWords.elements = [
    "a",
    "acuerdo",
    "adelante",
    "ademas",
    "ademas",
    "adrede",
    "ahi",
    "ahi",
    "ahora",
    "al",
    "alli",
    "alli",
    "alrededor",
    "antano",
    "antano",
    "ante",
    "antes",
    "apenas",
    "aproximadamente",
    "aquel",
    "aquel",
    "aquella",
    "aquella",
    "aquellas",
    "aquellas",
    "aquello",
    "aquellos",
    "aquellos",
    "aqui",
    "aqui",
    "arribaabajo",
    "asi",
    "asi",
    "aun",
    "aun",
    "aunque",
    "b",
    "bajo",
    "bastante",
    "bien",
    "breve",
    "c",
    "casi",
    "cerca",
    "claro",
    "como",
    "como",
    "con",
    "conmigo",
    "contigo",
    "contra",
    "cual",
    "cual",
    "cuales",
    "cuales",
    "cuando",
    "cuando",
    "cuanta",
    "cuanta",
    "cuantas",
    "cuantas",
    "cuanto",
    "cuanto",
    "cuantos",
    "cuantos",
    "d",
    "de",
    "debajo",
    "del",
    "delante",
    "demasiado",
    "dentro",
    "deprisa",
    "desde",
    "despacio",
    "despues",
    "despues",
    "detras",
    "detras",
    "dia",
    "dia",
    "dias",
    "dias",
    "donde",
    "donde",
    "dos",
    "durante",
    "e",
    "el",
    "el",
    "ella",
    "ellas",
    "ellos",
    "en",
    "encima",
    "enfrente",
    "enseguida",
    "entre",
    "es",
    "esa",
    "esa",
    "esas",
    "esas",
    "ese",
    "ese",
    "eso",
    "esos",
    "esos",
    "esta",
    "esta",
    "esta",
    "estado",
    "estados",
    "estan",
    "estan",
    "estar",
    "estas",
    "estas",
    "este",
    "este",
    "esto",
    "estos",
    "estos",
    "ex",
    "excepto",
    "f",
    "final",
    "fue",
    "fuera",
    "fueron",
    "g",
    "general",
    "gran",
    "h",
    "ha",
    "habia",
    "habia",
    "habla",
    "hablan",
    "hace",
    "hacia",
    "han",
    "hasta",
    "hay",
    "horas",
    "hoy",
    "i",
    "incluso",
    "informo",
    "informo",
    "j",
    "junto",
    "k",
    "l",
    "la",
    "lado",
    "las",
    "le",
    "lejos",
    "lo",
    "los",
    "luego",
    "m",
    "mal",
    "mas",
    "mas",
    "mayor",
    "me",
    "medio",
    "mejor",
    "menos",
    "menudo",
    "mi",
    "mi",
    "mia",
    "mia",
    "mias",
    "mias",
    "mientras",
    "mio",
    "mio",
    "mios",
    "mios",
    "mis",
    "mismo",
    "mucho",
    "muy",
    "n",
    "nada",
    "nadie",
    "ninguna",
    "no",
    "nos",
    "nosotras",
    "nosotros",
    "nuestra",
    "nuestras",
    "nuestro",
    "nuestros",
    "nueva",
    "nuevo",
    "nunca",
    "o",
    "os",
    "otra",
    "otros",
    "p",
    "pais",
    "pais",
    "para",
    "parte",
    "pasado",
    "peor",
    "pero",
    "poco",
    "por",
    "porque",
    "pronto",
    "proximo",
    "proximo",
    "puede",
    "q",
    "qeu",
    "que",
    "que",
    "quien",
    "quien",
    "quienes",
    "quienes",
    "quiza",
    "quiza",
    "quizas",
    "quizas",
    "r",
    "raras",
    "repente",
    "s",
    "salvo",
    "se",
    "se",
    "segun",
    "segun",
    "ser",
    "sera",
    "sera",
    "si",
    "si",
    "sido",
    "siempre",
    "sin",
    "sobre",
    "solamente",
    "solo",
    "solo",
    "son",
    "soyos",
    "su",
    "supuesto",
    "sus",
    "suya",
    "suyas",
    "suyo",
    "t",
    "tal",
    "tambien",
    "tambien",
    "tampoco",
    "tarde",
    "te",
    "temprano",
    "ti",
    "tiene",
    "todavia",
    "todavia",
    "todo",
    "todos",
    "tras",
    "tu",
    "tu",
    "tus",
    "tuya",
    "tuyas",
    "tuyo",
    "tuyos",
    "u",
    "un",
    "una",
    "unas",
    "uno",
    "unos",
    "usted",
    "ustedes",
    "v",
    "veces",
    "vez",
    "vosotras",
    "vosotros",
    "vuestra",
    "vuestras",
    "vuestro",
    "vuestros",
    "w",
    "x",
    "y",
    "ya",
    "yo",
    "z" ];

lunr.Pipeline.registerFunction(lunr.stopWordFilterSpanish, 'stopWordFilterSpanish');

lunr.stemmerSpanish = (function(word){
	var len;

	len = word.length - 1;
	
	word = word.replace(/ä/gi, "a");
    word = word.replace(/à/gi, "a");
    word = word.replace(/á/gi, "a");
    word = word.replace(/â/gi, "a");

    word = word.replace(/è/gi, "e");
    word = word.replace(/é/gi, "e");
    word = word.replace(/ê/gi, "e");

    word = word.replace(/ï/gi, "i");
    word = word.replace(/ì/gi, "i");
    word = word.replace(/í/gi, "i");
    word = word.replace(/î/gi, "i");

    word = word.replace(/ö/gi, "o");
    word = word.replace(/ò/gi, "o");
    word = word.replace(/ó/gi, "o");
    word = word.replace(/ô/gi, "o");

    word = word.replace(/ü/gi, "u");
    word = word.replace(/ù/gi, "u");
    word = word.replace(/ú/gi, "u");
    word = word.replace(/û/gi, "u");

    word = word.replace(/ç/gi, "c");
    word = word.replace(/ñ/gi, "n");
	
	 if (len > 2) {
        if ((word[len]=='s') && (word[len-1]=='e') && (word[len-2]=='s') && (word[len-3]=='e')) {
            /*  corteses -> cortés  */
            word = word.slice(0, len-1);
            return(word);
        }
        if ((word[len]=='s') && (word[len-1]=='e') && (word[len-2]=='c')) {
            word = word.replaceAt(len-2,'z');        /*  dos veces -> una vez  */
            word = word.slice(0, len-1);
            return(word);
        }
        if (word[len]=='s') {  /*  ending with -os, -as  or -es */
            if (word[len-1]=='o' || word[len-1]=='a' || word[len-1]=='e' ) {
                word = word.slice(0, len-1);  /*  remove -os, -as  or -es */
                return (word);
            }
        }
        if (word[len]=='o') {   /*  ending with  -o  */
            word = word.slice(0, len);
            return(word);
        }
        if (word[len]=='a') {   /*  ending with  -a  */
            word = word.slice(0, len);
            return(word);
        }
        if (word[len]=='e') {   /*  ending with  -e  */
            word = word.slice(0, len);
            return(word);
        }
    } /* end if (len > 3) */

	return word;
    
 });

lunr.Pipeline.registerFunction(lunr.stemmerSpanish, 'stemmerSpanish');

function changeLunrLanguageContext(lang){
    if (lang != 'en'){
        switch(lang){
            case 'de' :
                idx.pipeline.add(lunr.stopWordFilterGerman, lunr.stemmerGerman);
                break;
            case 'fr' :
                idx.pipeline.add(lunr.stopWordFilterFrench, lunr.stemmerFrench);
                break;
            case 'es' :
                idx.pipeline.add(lunr.stopWordFilterSpanish, lunr.stemmerSpanish);
                break;
            default:
                break;
        }
        idx.pipeline.remove(lunr.stemmer);
    }
}

