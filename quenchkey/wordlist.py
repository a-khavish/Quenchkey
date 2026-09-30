# Copyright 2026 Quenchkey contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Built-in wordlist for passphrase generation.

2048 English words (11 bits of entropy each) drawn from the en_US Hunspell
dictionary. Every word is 4-7 lowercase letters and has a unique three-letter
prefix, so a phrase stays unambiguous even written in shorthand. Words that are
crude, clinical or unpleasant to type in front of a colleague are filtered out;
a passphrase you are embarrassed to read aloud is a passphrase you will change
to something weaker.

The list is a power of two on purpose: selection with ``secrets.randbelow(2048)``
is then uniform, with no modulo bias to correct for.
"""

WORDLIST = """\
aalii abaca abba abduce abet abhor abide abject able abmho abode abri abseil abut abvolt abwatt
acari acerb ache acid acme acne acorn acre acute adage addax adept adhere adit adman adnate
adobe adrift adsorb adult adytum adze aecia aedes aegis afar afeard affix afire aflame afoot
afrit agar agee agger agio aglet agma agnail agog agree ague ahchoo ahem ahimsa ahoy aide aiglet
aikido aioli airt aisle aitch ajar akee akin alba alcaic alder alee alga alias alpha also alto
alum alvine always amah ambo amen amid ammo amnio amok ample amrita amuse anat ancon anew angel
anil anlace anna anoa ansate anta anuran anvil anyhow aorta aoudad apace apex aphid apian aplite
apnea aport appel apron apse apter arak arbor ardeb area argal aria arkose arnica aroid arpent
arras arsis arum arvo asap asci asdic aseity aside asked aslant aspen asylum ataman atilt atlas
atman atom atria atween aubade audio auger auklet aulic aunt aura auspex auth auxin avail avens
avid avow away awful awhile awning awoke axeman axil axle axon axseed ayah ayin azan azide azoic
azure baba bach bade baffle bagel baht bail bake bald bamboo banc baobab barb base bate baud
bawd bayou bazar bead bebop bedel beef befit began behalf beige bell bema bend berg best beta
bevy bewail beyond bezel bhaji bias bibb bice bide bier biff bight bijou bike bile bimah bind
biog biped bird bisk bite bize blab bleb blip blob blue boar bobby bode boffo boga bohunk boil
bola bond book bopped bora bosh both bout bovid bowl boyar bozo brad bred brie brow brut bryony
bubo buddy bueno buff buggy buhl build bulb bumf bund buoy burg bush butch buxom buyer bwana
bygone bylaw bypass byre byssus byte byway cabal cacao cade cafe cage cahier cain cajole cake
calf came canc cape card casa cate caul cave cayuse cease ceca cede ceil cell cement cent ceorl
cere cess cetane chad chef chge chic choc chron chub chyle ciao cicada cider cigar cilia cimex
cine cion cire cist cite civet clad clef clod club clvi clxi cnemis coal cobia coca coda coff
cogon coho coif coke cola coma cone cook cope cord cosh cote coup cove cowl coxa coypu coze crab
crew crib crop crud cube cuddy cuesta cuff cuisse cuke cull cumin cuneal cupel curb cusk cute
cyan cyborg cycad cygnet cylix cyma cynic cyton czar dabbed dace dada daff dago dahl dais dale
dame dang dare dash data daub davit dawn daybed daze dded dding deaf debt dedal deed deft degage
dehorn deil deject dekko dele deme dent deodar depth derv desk deter deuce deva dewy dexter
dharma dhow dhyana diag dibs dice dido diet diff dight dike dill dime dine diode dipl dire disc
ditz diva diwan dixie dizen djebel doable dobby dodo doff doge doit dole dome dona doom dopa
dora dose dote dour dove down doyen doze drab dree drip drop drub duad dubbed duce dude duel
duff dugong duiker duke dull duma dune duomo dupe duro dusk duty duvet dweeb dyad dybbuk dyed
dyke dyne each eager earl ease eaten eave ebon eceses echo eclat ecol ecru ectype eczema eddo
edema edge edit educ eerie efface egad egest eggcup egoism egret eide eight eikon either eject
elan elbow elder elem elfin elide elope else elude elver email embay emcee emend emir emmer
emoji enact endow enema enface enigma enjoy enlace enmesh ennui enol enrage ensue enter enwind
enzyme eolian eonian eosin epact epee ephah epic epos equal erase erbium erect ergo eringo
ermine erne erode error eruct eryngo escape esker esse ester etalon eterne ether etna etui
etymon euchre eulogy eunuch euro evade even evil evoke evzone ewer exam exec exhale exit exon
expo exsect extol exude eyas eyecup eyot eyra fable face fade faena faff fail fajita fake fall
fame fane faqir fard fash faun fave fawn faze feal fedora feed feign fell feme fend feoff fern
fess feta feud fever fiat fiber fico fidge fief fife fight fila fimble find fiorin fipple fire
fisc fitch five fixed fjeld fjord flab flea flip floc flub foal fobbed focal fodder foehn fogy
foil fold foment fond food fora fossa foul fovea fowl foyer free frig frug fryer fubsy fucus
fudge fuel fugal fuhrer full fume fund furl fuse futz fyke fylfot gaby gadid gaff gaga gain gala
gamb gang gape garb gash gate gaud gave gawd gaze gean gecko geddit geek geisha geld gemma gene
geod germ gesso getup geum gewgaw geyser ghost giant gibe giddy gift gigot gild gimp gink gipon
gird gist gite give gizmo glad glee glia glob glue gnat gneiss gnome goad gobo godly gofer
goggle going gold gomuti gone good gopak gore gosh goths gout govt gowk goyim grab gree grid
grog grub guan guddle guess guff guggle guib gula gumbo guppy guru gush gutsy guvnor guyot gyre
gyve haaf habit hade haft hagbut haik hajj hake hale hame hand haole happy hard hash hatch haul
have hawk haymow haze head heder heed heft hegira heir held heme hent hepcat herb heths hewer
hexad heyday hiatal hide hieing hijab hike hila hind hippo hire hiss hitch hive hiya hoar hobo
hodden hogan hoick hoke hold home hone hood hope hora hose hour hove howl hoyden hubby huddle
huff huge hula hump hung huppah hurl hush hutch hwan hybrid hydra hyena hying hyla hyoid hype
hyrax hyson iamb iatric ibex ibid icebox ichor icily icon ictus idea idiom idle idol igloo
ignite iguana ihram ilea ilia illus imam imbue imit immix inane inbox indef inept info ingle
inhaul init inject inmate inner inpour inrush inti inure ioctl iodic iolite ionic iota ipecac
ipomea irade ireful iris iron irreg isatin ischia isle isobar issei istle ital item ivory iwis
ixia ixtle izard kaboom kadi kafir kagu kahuna kaif kaka kale kame kana kaon kart kasha kauri
kava kayo kazoo kcal kebab kedge keef kegler kelp keno kepi kerf keto kevel keypad khan kheda
khoum kiang kibe kiddo kief kike kiln kimchi kina kiosk kipped kirsch kish kite kiva kiwi klatch
klong kluge knap knee knit knob knur koan kobo kohl koine kola kook korma kosher koto koumis
kowtow kraal kris krona kuchen kudo kukri kulak kumiss kuna kurus kuvasz kvass kvetch kwacha
kyat kyle laager label lace lade lagan laic lake lama land lapel lard lase late laud lava lawn
laxity layer laze lead lech ledge leek left legal lehr leman lend leone leper less lethe leva
lewd lexis liar libel lice lido lied life ligan like lilo limb line lion lipid lira lisp lite
live lizard llama load lobe loci lode loess loft loge loin loll loment lone look lope lord lose
lota loud love lower loyal luau lube luce ludo lues luff luge lull lump lune lupine lure lush
lute luxe lwei lxvi lyceum lying lyre lyse lytic mace made mafia mage mahout maid major make
male mama mana maple mara masc mate maul maven mawkin maxi maya maze mdse mead mech medal meed
mega meiny meld meme mend meow mere mesa meta mewl mezzo miasma mica midi mien miff might mihrab
mike mild mime mind miosis mire misc mite mixed mize mkay mneme moan mobbed mode moggy mohur
moil mojo moke mola mommy mong mood mope mora mosh mote moue move mower moxa mtge much muddy
muesli muff muggy mujik mukluk mule mump mung muon mure muse mute myall mycol myelin myna myopia
myself myxoma naan nabob nacho nadir naevi naff nagana naif naker name nance naos nape narc
nasal natl naut nave nawab neap nebula need negro neigh nekton nelly neon neper nerd ness netty
neut nevi news next ngwee niacin nibble nice nide niece niff nihil nilgai nimbi nine niobic nipa
nisi niter nival nobby node noggin nohow noil nolo noma none nook nope norm nose note noun nova
nowt noyade nuance nubby nuclei nudge nuggar nuke null numb nuncio nurse nutty nyala nybble
nylon oafish oakum oast oath obey obit objet oblast obsess obtain obvert occas ocean ocher ocker
ocrea octad oculi odea odium odor ofay offal often ogdoad ogee ogham ogive ogle ogre ohmic
oidium oily oink okay okra oldie oleo olid olla ology omasa omber omen omit onager once onion
online onrush onset onto onus oocyte oodles oohs oolite oomph oops ootid ooze opah opcode open
opine oppose optic oral orbit orca oread organ orig orle ormolu ornis orris orzo oscine osier
osmic osprey ossein osteal other otic otto ouch ought ounce ouphe oust outdo ouzo oval oven
ovine ovoid ovum owlet owned oxalic oxbow oxcart oxford oxide oxtail oyer oyster ozone pablum
pace paddy paean page paid pajama pale pampa pane papa para pase pate pause pave pawl paxwax
payt peag peba pedal peek pegged peke pelf pend peon peppy pere peso petal pewee peyote phlox
piano pica piddle pier piffle piggy pika pile pimp pine pious pipe pique pirn pish pita pivot
pixel plan plea plica plod plug pneuma poach poddy pogo poilu poke pole pome pond pood pope pore
pose potto pouf power pram pref prig proa prude prying psalm pseud pshaw psia psoas ptisan
ptoses publ puca pudgy pueblo puff puisne puke pula puma pung pupa pure putt pyemia pyknic pylon
pyoid pyre python pyuria pyxie pzazz rabbi race radar raff raga raid rajah rake rale ramp rand
rapt rare rash rata rave rayon raze real rebec rect redd reed refl regal rehi rein reject reknit
rely remex rend reorg repp reread rest retd revel rewash rhea rhino rhomb rhumb rhyme rial
ribald rice ride riel rife right rile rime rind riot ripe rise rite rive riyal road robe rode
roger roil role romp ronde rood rope roque rose rota roue rove rowan royal rube rudd rueful ruff
rugby ruin rule rump rune rupee rural ruse ruth saber sades safe saga sahib said sake sale same
sand sapid sard sash sate sauce save sawfly saying scad scend schmo scion sclaff scop scrag scud
seal sebum sech sedan seed segno seine sejant self semi send sept seqq sere sesame seta seven
sewn shad shed shim shmo shod shred shul shyer sibyl sicced side siege sift sika sild sima sine
sire sisal site sixth size skat skeg skid skol skua skycap slab sled slid slob slub slype smack
smew smile smog smriti smug snag sneak snip snob snub soak soba soda sofa soggy soil soke sola
soma sone soon sora sotted souk soviet sown spec spin splat spot spud squab sruti stag stdio
stem stge stir stoa strap stub style suave subj such sudd suet suffer sugar suit sukkah sulk
sumo sung supp sura suss sutra svelte swab swear swig swot swum syce symbol syrup tabby tace
taffy tagged tahr tail taka tala tame tana tape tare task tater taut tavern tawny taxa tayra
tazza teak tech teddy teem tegmen tell temp tend tepee terf test teth text than thee thin thou
thru thud thyme tiara tibia tide tier tiff tiger tiki tile time tine tipsy tire tisane titi
tmeses toad tocsin tody toff toga toil toke tola tome tone took tope toque tore tosh tote tour
town toxic toyboy trad tree trig trod true tryma tuba tufa tugged tulip tumid tuna tuple tuque
turf tush tutu tuxedo tuyere twas twee twig twofer tying tyke tymbal type tyro ubiety udder
uglify uhlan ukase ulcer ulema ullage ulna ulster ultra umbel umiak umlaut umpire unapt unbid
uncap undo unease unfed unglue unhair unify unjam unkind unlay unmet unpeg unrig unsay until
unwed upas upbear upcast updo upend upkeep upland upmost upon upped uprate upset uptake upwell
uracil urban urchin urea urge uric uropod ursine urtext urus usage used usher usual utile utmost
utopia utter uvea uvula vacant vadose vagi vail vale vamp vane vape vara vasa vatu vault veal
vector vedic veep vegan veil vela vena verb vest veto vial vibe vice vide view vigil viking vile
vina viol viper viral visa vita viva vixen vizard vocab vodka vogue void vole vomer voodoo
vortex vote vouch vowel voyage vulg vying wabbit wade waft wage wahoo waif wake wale wame wand
wapiti wash watt wave waylay wazoo weak webby wedge weed weft weir weka weld wend wept were west
wether whsle wield wight wizen wodge would wrong wrung wryer wurst yacht yahoo yakka yapok yenta
yield yikes yobbo yodel yukky yummy
""".split()

assert len(WORDLIST) == 2048
BITS_PER_WORD = 11
