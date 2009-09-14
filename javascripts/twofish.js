/*!Copyright (c) 2009 pidder <www.pidder.com>*/
/*----------------------------------------------------------------------------*/
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*
*  Twofish CBC (Cipher Block Chaining) Mode for use in pidCrypt Library
*
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js) and MD5 (md5.js)
*
/*----------------------------------------------------------------------------*/

if(typeof(pidCrypt) != 'undefined')
{
  pidCrypt.Twofish = function (env)
  {
    this.env = (env) ? env : new pidCrypt();
    this.tfsKey=[];
    this.tfsM=[[],[],[],[]];
    this.wMax = 0xFFFFFFFF;
  }

  pidCrypt.Twofish.prototype.getW = function(a,i)
  {
    var w32 = a[i]|a[i+1]<<8|a[i+2]<<16|a[i+3]<<24;
//    var w32 = a[i+3]|a[i+2]<<8|a[i+1]<<16|a[i]<<24;
    return w32;
  }
  
  pidCrypt.Twofish.prototype.setW = function(a,i,w)
  {
    a.splice(i,4,w&0xFF,(w>>>8)&0xFF,(w>>>16)&0xFF,(w>>>24)&0xFF);
  }

  pidCrypt.Twofish.prototype.getB = function(x,n)
  {
    var shift = n*8;
    var b = x>>>shift
    b = b&0xFF;
    return b;
  }

  pidCrypt.Twofish.prototype.rotw = function(w,n)
  {
    return w<<n | (w>>>(32-n)) & this.wMax;
  }

  pidCrypt.Twofish.prototype.init = function(key)
  {
    var  i, a, b, c, d, meKey=[], moKey=[], inKey=[];
    var kLen;
    var sKey=[];
    //var  f01, f5b, fef;

    var q0=[[8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4],[2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5]];
    var q1=[[14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13],[1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8]];
    var q2=[[11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1],[4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15]];
    var q3=[[13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10],[11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10]];
    var q=[
            [
             169, 103, 179, 232, 4, 253, 163, 118, 154, 146, 128, 120, 228, 221, 209,
             56, 13, 198, 53, 152, 24, 247, 236, 108, 67, 117, 55, 38, 250, 19, 148,
             72, 242, 208, 139, 48, 132, 84, 223, 35, 25, 91, 61, 89, 243, 174, 162,
             130, 99, 1, 131, 46, 217, 81, 155, 124, 166, 235, 165, 190, 22, 12, 227,
             97, 192, 140, 58, 245, 115, 44, 37, 11, 187, 78, 137, 107, 83, 106, 180,
             241, 225, 230, 189, 69, 226, 244, 182, 102, 204, 149, 3, 86, 212, 28, 30,
             215, 251, 195, 142, 181, 233, 207, 191, 186, 234, 119, 57, 175, 51, 201,
             98, 113, 129, 121, 9, 173, 36, 205, 249, 216, 229, 197, 185, 77, 68, 8,
             134, 231, 161, 29, 170, 237, 6, 112, 178, 210, 65, 123, 160, 17, 49, 194,
             39, 144, 32, 246, 96, 255, 150, 92, 177, 171, 158, 156, 82, 27, 95, 147,
             10, 239, 145, 133, 73, 238, 45, 79, 143, 59, 71, 135, 109, 70, 214, 62,
             105, 100, 42, 206, 203, 47, 252, 151, 5, 122, 172, 127, 213, 26, 75, 14,
             167, 90, 40, 20, 63, 41, 136, 60, 76, 2, 184, 218, 176, 23, 85, 31, 138,
             125, 87, 199, 141, 116, 183, 196, 159, 114, 126, 21, 34, 18, 88, 7, 153,
             52, 110, 80, 222, 104, 101, 188, 219, 248, 200, 168, 43, 64, 220, 254,
             50, 164, 202, 16, 33, 240, 211, 93, 15, 0, 111, 157, 54, 66, 74, 94, 193,
             224
            ],
            [
              117, 243, 198, 244, 219, 123, 251, 200, 74, 211, 230, 107, 69, 125, 232,
              75, 214, 50, 216, 253, 55, 113, 241, 225, 48, 15, 248, 27, 135, 250, 6,
              63, 94, 186, 174, 91, 138, 0, 188, 157, 109, 193, 177, 14, 128, 93, 210,
              213, 160, 132, 7, 20, 181, 144, 44, 163, 178, 115, 76, 84, 146, 116, 54,
              81, 56, 176, 189, 90, 252, 96, 98, 150, 108, 66, 247, 16, 124, 40, 39,
              140, 19, 149, 156, 199, 36, 70, 59, 112, 202, 227, 133, 203, 17, 208,
              147, 184, 166, 131, 32, 255, 159, 119, 195, 204, 3, 111, 8, 191, 64, 231,
              43, 226, 121, 12, 170, 130, 65, 58, 234, 185, 228, 154, 164, 151, 126,
              218, 122, 23, 102, 148, 161, 29, 61, 240, 222, 179, 11, 114, 167, 28,
              239, 209, 83, 62, 143, 51, 38, 95, 236, 118, 42, 73, 129, 136, 238, 33,
              196, 26, 235, 217, 197, 57, 153, 205, 173, 49, 139, 1, 24, 35, 221, 31,
              78, 45, 249, 72, 79, 242, 101, 142, 120, 92, 88, 25, 141, 229, 152, 87,
              103, 127, 5, 100, 175, 99, 182, 254, 245, 183, 60, 165, 206, 233, 104,
              68, 224, 77, 67, 105, 41, 46, 172, 21, 89, 168, 10, 158, 110, 71, 223,
              52, 53, 106, 207, 220, 34, 201, 192, 155, 137, 212, 237, 171, 18, 162,
              13, 82, 187, 2, 47, 169, 215, 97, 30, 180, 80, 4, 246, 194, 22, 37, 134,
              86, 85, 9, 190, 145
            ]
           ];
    var m=[[
            3166450293, 3974898163, 538985414, 3014904308, 3671720923,
            33721211, 3806473211, 2661219016, 3385453642, 3570665939,
            404253670, 505323371, 2560101957, 2998024317, 2795950824,
            640071499, 1010587606, 2475919922, 2189618904, 1381144829,
            2071712823, 3149608817, 1532729329, 1195869153, 606354480,
            1364320783, 3132802808, 1246425883, 3216984199, 218984698,
            2964370182, 1970658879, 3537042782, 2105352378, 1717973422,
            976921435, 1499012234, 0, 3452801980, 437969053, 2930650221,
            2139073473, 724289457, 3200170254, 3772817536, 2324303965,
            993743570, 1684323029, 3638069408, 3890718084, 1600120839,
            454758676, 741130933, 4244419728, 825304876, 2155898275,
            1936927410, 202146163, 2037997388, 1802191188, 1263207058,
            1397975412, 2492763958, 2206408529, 707409464, 3301219504,
            572704957, 3587569754, 3183330300, 1212708960, 4294954594,
            1280051094, 1094809452, 3351766594, 3958056183, 471602192,
            1566401404, 909517352, 1734852647, 3924406156, 1145370899,
            336915093, 4126522268, 3486456007, 1061104932, 3233866566,
            1920129851, 1414818928, 690572490, 4042274275, 134807173,
            3334870987, 4092808977, 2358043856, 2762234259, 3402274488,
            1751661478, 3099086211, 943204384, 3857002239, 2913818271,
            185304183, 3368558019, 2577006540, 1482222851, 421108335,
            235801096, 2509602495, 1886408768, 4160172263, 1852755755,
            522153698, 3048553849, 151588620, 1633760426, 1465325186,
            2678000449, 2644344890, 286352618, 623234489, 2947538404,
            1162152090, 3755969956, 2745392279, 3941258622, 892688602,
            3991785594, 1128528919, 4177054566, 4227576212, 926405537,
            4210704413, 3267520573, 3031747824, 842161630, 2627498419,
            1448535819, 3823360626, 2273796263, 353704732, 4193860335,
            1667481553, 875866451, 2593817918, 2981184143, 2088554803,
            2290653990, 1027450463, 2711738348, 3840204662, 2172752938,
            2442199369, 252705665, 4008618632, 370565614, 3621221153,
            2543318468, 2779097114, 4278075371, 1835906521, 2021174981,
            3318050105, 488498585, 1987486925, 1044307117, 3419105073,
            3065399179, 4025441025, 303177240, 1616954659, 1785376989,
            1296954911, 3469666638, 3739122733, 1431674361, 2122209864,
            555856463, 50559730, 2694850149, 1583225230, 1515873912,
            1701137244, 1650609752, 4261233945, 101119117, 1077970661,
            4075994776, 859024471, 387420263, 84250239, 3907542533,
            1330609508, 2307484335, 269522275, 1953771446, 168457726,
            1549570805, 2610656439, 757936956, 808507045, 774785486,
            1229556201, 1179021928, 2004309316, 2829637856, 2526413901,
            673758531, 2846435689, 3654908201, 2256965934, 3520169900,
            4109650453, 2374833497, 3604382376, 3115957258, 1111625118,
            4143366510, 791656519, 3722249951, 589510964, 3435946549,
            4059153514, 3250655951, 2240146396, 2408554018, 1903272393,
            2425417920, 2863289243, 16904585, 2341200340, 1313770733,
            2391699371, 2880152082, 1869561506, 3873854477, 3688624722,
            2459073467, 3082270210, 1768540719, 960092585, 3553823959,
            2812748641, 2728570142, 3284375988, 1819034704, 117900548,
            67403766, 656885442, 2896996118, 3503322661, 1347425158,
            3705468758, 2223250005, 3789639945, 2054825406, 320073617
           ],
           [
            2849585465, 1737496343, 3010567324, 3906119334, 67438343,
            4254618194, 2741338240, 1994384612, 2584233285, 2449623883,
            2158026976, 2019973722, 3839733679, 3719326314, 3518980963,
            943073834, 223667942, 3326287904, 895667404, 2562650866,
            404623890, 4146392043, 3973554593, 1819754817, 1136470056,
            1966259388, 936672123, 647727240, 4201647373, 335103044,
            2494692347, 1213890174, 4068082435, 3504639116, 2336732854,
            809247780, 2225465319, 1413573483, 3741769181, 600137824,
            424017405, 1537423930, 1030275778, 1494584717, 4079086828,
            2922473062, 2722000751, 2182502231, 1670713360, 22802415,
            2202908856, 781289094, 3652545901, 1361019779, 2605951658,
            2086886749, 2788911208, 3946839806, 2782277680, 3190127226,
            380087468, 202311945, 3811963120, 1629726631, 3236991120,
            2360338921, 981507485, 4120009820, 1937837068, 740766001,
            628543696, 199710294, 3145437842, 1323945678, 2314273025,
            1805590046, 1403597876, 1791291889, 3029976003, 4053228379,
            3783477063, 3865778200, 3184009762, 1158584472, 3798867743,
            4106859443, 3056563316, 1724643576, 3439303065, 2515145748,
            65886296, 1459084508, 3571551115, 471536917, 514695842,
            3607942099, 4213957346, 3273509064, 2384027230, 3049401388,
            3918088521, 3474112961, 3212744085, 3122691453, 3932426513,
            2005142283, 963495365, 2942994825, 869366908, 3382800753,
            1657733119, 1899477947, 2180714255, 2034087349, 156361185,
            2916892222, 606945087, 3450107510, 4187837781, 3639509634,
            3850780736, 3316545656, 3117229349, 1292146326, 1146451831,
            134876686, 2249412688, 3878746103, 2714974007, 490797818,
            2855559521, 3985395278, 112439472, 1886147668, 2989126515,
            3528604475, 1091280799, 2072707586, 2693322968, 290452467,
            828885963, 3259377447, 666920807, 2427780348, 539506744,
            4135519236, 1618495560, 4281263589, 2517060684, 1548445029,
            2982619947, 2876214926, 2651669058, 2629563893, 1391647707,
            468929098, 1604730173, 2472125604, 180140473, 4013619705,
            2448364307, 2248017928, 1224839569, 3999340054, 763158238,
            1337073953, 2403512753, 1004237426, 1203253039, 2269691839,
            1831644846, 1189331136, 3596041276, 1048943258, 1764338089,
            1685933903, 714375553, 3460902446, 3407333062, 801794409,
            4240686525, 2539430819, 90106088, 2060512749, 2894582225,
            2140013829, 3585762404, 447260069, 1270294054, 247054014,
            2808121223, 1526257109, 673330742, 336665371, 1071543669,
            695851481, 2292903662, 1009986861, 1281325433, 45529015,
            3096890058, 3663213877, 2963064004, 402408259, 1427801220,
            536235341, 2317113689, 2100867762, 1470903091, 3340292047,
            2381579782, 1953059667, 3077872539, 3304429463, 2673257901,
            1926947811, 2127948522, 357233908, 580816783, 312650667,
            1481532002, 132669279, 2581929245, 876159779, 1858205430,
            1346661484, 3730649650, 1752319558, 1697030304, 3163803085,
            3674462938, 4173773498, 3371867806, 2827146966, 735014510,
            1079013488, 3706422661, 4269083146, 847942547, 2760761311,
            3393988905, 269753372, 561240023, 4039947444, 3540636884,
            1561365130, 266490193, 0, 1872369945, 2648709658, 915379348,
            1122420679, 1257032137, 1593692882, 3249241983, 3772295336
           ],
           [
            3161832498, 3975408673, 549855299, 3019158473, 3671841283,
            41616011, 3808158251, 2663948026, 3377121772, 3570652169,
            417732715, 510336671, 2554697742, 2994582072, 2800264914,
            642459319, 1020673111, 2469565322, 2195227374, 1392333464,
            2067233748, 3144792887, 1542544279, 1205946243, 607134780,
            1359958498, 3136862918, 1243302643, 3213344584, 234491248,
            2953228467, 1967093214, 3529429757, 2109373728, 1722705457,
            979057315, 1502239004, 0, 3451702675, 446503648, 2926423596,
            2143387563, 733031367, 3188637369, 3766542496, 2321386000,
            1003633490, 1691706554, 3634419848, 3884246949, 1594318824,
            454302481, 750070978, 4237360308, 824979751, 2158198885,
            1941074730, 208866433, 2035054943, 1800694593, 1267878658,
            1400132457, 2486604943, 2203157279, 708323894, 3299919004,
            582820552, 3579500024, 3187457475, 1214269560, 4284678094,
            1284918279, 1097613687, 3343042534, 3958893348, 470817812,
            1568431459, 908604962, 1730635712, 3918326191, 1142113529,
            345314538, 4120704443, 3485978392, 1059340077, 3225862371,
            1916498651, 1416647788, 701114700, 4041470005, 142936318,
            3335243287, 4078039887, 2362477796, 2761139289, 3401108118,
            1755736123, 3095640141, 941635624, 3858752814, 2912922966,
            192351108, 3368273949, 2580322815, 1476614381, 426711450,
            235408906, 2512360830, 1883271248, 4159174448, 1848340175,
            534912878, 3044652349, 151783695, 1638555956, 1468159766,
            2671877899, 2637864320, 300552548, 632890829, 2951000029,
            1167738120, 3752124301, 2744623964, 3934186197, 903492952,
            3984256464, 1125598204, 4167497931, 4220844977, 933312467,
            4196268608, 3258827368, 3035673804, 853422685, 2629016689,
            1443583719, 3815957466, 2275903328, 354161947, 4193253690,
            1674666943, 877868201, 2587794053, 2978984258, 2083749073,
            2284226715, 1029651878, 2716639703, 3832997087, 2167046548,
            2437517569, 260116475, 4001951402, 384702049, 3609319283,
            2546243573, 2769986984, 4276878911, 1842965941, 2026207406,
            3308897645, 496573925, 1993176740, 1051541212, 3409038183,
            3062609479, 4009881435, 303567390, 1612931269, 1792895664,
            1293897206, 3461271273, 3727548028, 1442403741, 2118680154,
            558834098, 66192250, 2691014694, 1586388505, 1517836902,
            1700554059, 1649959502, 4246338885, 109905652, 1088766086,
            4070109886, 861352876, 392632208, 92210574, 3892701278,
            1331974013, 2309982570, 274927765, 1958114351, 184420981,
            1559583890, 2612501364, 758918451, 816132310, 785264201,
            1240025481, 1181238898, 2000975701, 2833295576, 2521667076,
            675489981, 2842274089, 3643398521, 2251196049, 3517763975,
            4095079498, 2371456277, 3601389186, 3104487868, 1117667853,
            4134467265, 793194424, 3722435846, 590619449, 3426077794,
            4050317764, 3251618066, 2245821931, 2401406878, 1909027233,
            2428539120, 2862328403, 25756145, 2345962465, 1324174988,
            2393607791, 2870127522, 1872916286, 3859670612, 3679640562,
            2461766267, 3070408630, 1764714954, 967391705, 3554136844,
            2808194851, 2719916717, 3283403673, 1817209924, 117704453,
            83231871, 667035462, 2887167143, 3492139126, 1350979603,
            3696680183, 2220196890, 3775521105, 2059303461, 328274927
           ],
           [
            3644434905, 2417452944, 1906094961, 3534153938, 84345861,
            2555575704, 1702929253, 3756291807, 138779144, 38507010,
            2699067552, 1717205094, 3719292125, 2959793584, 3210990015,
            908736566, 1424362836, 1126221379, 1657550178, 3203569854,
            504502302, 619444004, 3617713367, 2000776311, 3173532605,
            851211570, 3564845012, 2609391259, 1879964272, 4181988345,
            2986054833, 1518225498, 2047079034, 3834433764, 1203145543,
            1009004604, 2783413413, 1097552961, 115203846, 3311412165,
            1174214981, 2738510755, 1757560168, 361584917, 569176865,
            828812849, 1047503422, 374833686, 2500879253, 1542390107,
            1303937869, 2441490065, 3043875253, 528699679, 1403689811,
            1667071075, 996714043, 1073670975, 3593512406, 628801061,
            2813073063, 252251151, 904979253, 598171939, 4036018416,
            2951318703, 2157787776, 2455565714, 2165076865, 657533991,
            1993352566, 3881176039, 2073213819, 3922611945, 4043409905,
            2669570975, 2838778793, 3304155844, 2579739801, 2539385239,
            2202526083, 1796793963, 3357720008, 244860174, 1847583342,
            3384014025, 796177967, 3422054091, 4288269567, 3927217642,
            3981968365, 4158412535, 3784037601, 454368283, 2913083053,
            215209740, 736295723, 499696413, 425627161, 3257710018,
            2303322505, 314691346, 2123743102, 545110560, 1678895716,
            2215344004, 1841641837, 1787408234, 3514577873, 2708588961,
            3472843470, 935031095, 4212097531, 1035303229, 1373702481,
            3695095260, 759112749, 2759249316, 2639657373, 4001552622,
            2252400006, 2927150510, 3441801677, 76958980, 1433879637,
            168691722, 324044307, 821552944, 3543638483, 1090133312,
            878815796, 2353982860, 3014657715, 1817473132, 712225322,
            1379652178, 194986251, 2332195723, 2295898248, 1341329743,
            1741369703, 1177010758, 3227985856, 3036450996, 674766888,
            2131031679, 2018009208, 786825006, 122459655, 1264933963,
            3341529543, 1871620975, 222469645, 3153435835, 4074459890,
            4081720307, 2789040038, 1503957849, 3166243516, 989458234,
            4011037167, 4261971454, 26298625, 1628892769, 2094935420,
            2988527538, 1118932802, 3681696731, 3090106296, 1220511560,
            749628716, 3821029091, 1463604823, 2241478277, 698968361,
            2102355069, 2491493012, 1227804233, 398904087, 3395891146,
            3284008131, 1554224988, 1592264030, 3505224400, 2278665351,
            2382725006, 3127170490, 2829392552, 3072740279, 3116240569,
            1619502944, 4174732024, 573974562, 286987281, 3732226014,
            2044275065, 2867759274, 858602547, 1601784927, 3065447094,
            2529867926, 1479924312, 2630135964, 4232255484, 444880154,
            4132249590, 475630108, 951221560, 2889045932, 416270104,
            4094070260, 1767076969, 1956362100, 4120364277, 1454219094,
            3672339162, 3588914901, 1257510218, 2660180638, 2729120418,
            1315067982, 3898542056, 3843922405, 958608441, 3254152897,
            1147949124, 1563614813, 1917216882, 648045862, 2479733907,
            64674563, 3334142150, 4204710138, 2195105922, 3480103887,
            1349533776, 3951418603, 1963654773, 2324902538, 2380244109,
            1277807180, 337383444, 1943478643, 3434410188, 164942601,
            277503248, 3796963298, 0, 2585358234, 3759840736, 2408855183,
            3871818470, 3972614892, 4258422525, 2877276587, 3634946264
           ]
         ];
    function mdsRem(p,q)
    {
      var i,t,u;
      for(i=0; i<8; i++){
        t = q>>>24;
        q = ((q<<8)&this.wMax) | p>>>24;
        p = (p<<8)&this.wMax;
        u = t<<1;
        if (t&128)
          u^=333;
        q ^= t^(u<<16);
        u ^= t>>>1; 
          if (t&1)
            u^=166;
        q ^= u<<24 | u<<8;
      }
      return q;
    }

 
    function hFun(x,key,instance)
    {
      var w;
      var ai = instance.getB(x,0);
      var bi = instance.getB(x,1);
      var ci = instance.getB(x,2);
      var di = instance.getB(x,3);
      switch(kLen){
      case 4:
        ai = q[1][ai]^instance.getB(key[3],0);
        bi = q[0][bi]^instance.getB(key[3],1);
        ci = q[0][ci]^instance.getB(key[3],2);
        di = q[1][di]^instance.getB(key[3],3);
      case 3:
        ai = q[1][ai]^instance.getB(key[2],0);
        bi = q[1][bi]^instance.getB(key[2],1);
        ci = q[0][ci]^instance.getB(key[2],2);
        di = q[0][di]^instance.getB(key[2],3);
      case 2:
        ai = q[0][q[0][ai]^instance.getB(key[1],0)]^instance.getB(key[0],0);
        bi = q[0][q[1][bi]^instance.getB(key[1],1)]^instance.getB(key[0],1);
        ci = q[1][q[0][ci]^instance.getB(key[1],2)]^instance.getB(key[0],2);
        di = q[1][q[1][di]^instance.getB(key[1],3)]^instance.getB(key[0],3);
      }
      w = m[0][ai]^m[1][bi]^m[2][ci]^m[3][di];
      return w;
    }

    key=key.slice(0,32);
    i=key.length;
    while ( i!=16 && i!=24 && i!=32 ) key[i++]=0;

    for (i=0; i<key.length; i+=4)
    {
      inKey[i>>2]=this.getW(key,i);
    }
    kLen = inKey.length/2;
    for (i=0; i<kLen; i++)
    {
      a = inKey[i+i];
      meKey[i] = a;
      b = inKey[i+i+1];
      moKey[i] = b;
      sKey[kLen-i-1] = mdsRem(a,b);
    }
    for (i=0; i<40; i+=2)
    {
      a=0x1010101*i;
      b=a+0x1010101;
      a=hFun(a,meKey,this);
      b=this.rotw(hFun(b,moKey,this),8);
      this.tfsKey[i]=(a+b)&this.wMax;
      this.tfsKey[i+1]=this.rotw(a+2*b,9);
    }
    for (i=0; i<256; i++)
    {
      a=b=c=d=i;
      switch(kLen)
      {
        case 4:
          a = q[1][a]^this.getB(sKey[3],0);
          b = q[0][b]^this.getB(sKey[3],1);
          c = q[0][c]^this.getB(sKey[3],2);
          d = q[1][d]^this.getB(sKey[3],3);
        case 3:
          a = q[1][a]^this.getB(sKey[2],0);
          b = q[1][b]^this.getB(sKey[2],1);
          c = q[0][c]^this.getB(sKey[2],2);
          d = q[0][d]^this.getB(sKey[2],3);
        case 2:
          this.tfsM[0][i] = m[0][q[0][q[0][a]^this.getB(sKey[1],0)]^this.getB(sKey[0],0)];
          this.tfsM[1][i] = m[1][q[0][q[1][b]^this.getB(sKey[1],1)]^this.getB(sKey[0],1)];
          this.tfsM[2][i] = m[2][q[1][q[0][c]^this.getB(sKey[1],2)]^this.getB(sKey[0],2)];
          this.tfsM[3][i] = m[3][q[1][q[1][d]^this.getB(sKey[1],3)]^this.getB(sKey[0],3)];
      }
    }
  }

  pidCrypt.Twofish.prototype.G0 = function(x)
  {
    return this.tfsM[0][this.getB(x,0)]^this.tfsM[1][this.getB(x,1)]^this.tfsM[2][this.getB(x,2)]^this.tfsM[3][this.getB(x,3)];
  }

  pidCrypt.Twofish.prototype.G1 = function(x)
  {
    return this.tfsM[0][this.getB(x,3)]^this.tfsM[1][this.getB(x,0)]^this.tfsM[2][this.getB(x,1)]^this.tfsM[3][this.getB(x,2)];
  }

  pidCrypt.Twofish.prototype.frnd = function(r,blk)
  {
    var a=this.G0(blk[0]);
    var b=this.G1(blk[1]);
    blk[2] = this.rotw( blk[2]^(a+b+this.tfsKey[4*r+8])&this.wMax, 31 );
    blk[3] = this.rotw(blk[3],1) ^ (a+2*b+this.tfsKey[4*r+9])&this.wMax;
    a=this.G0(blk[2]);
    b=this.G1(blk[3]);
    blk[0] = this.rotw( blk[0]^(a+b+this.tfsKey[4*r+10])&this.wMax, 31 );
    blk[1] = this.rotw(blk[1],1) ^ (a+2*b+this.tfsKey[4*r+11])&this.wMax;
  }


  pidCrypt.Twofish.prototype.irnd = function(i,blk)
  {
    var a=this.G0(blk[0]);
    var b=this.G1(blk[1]);
    blk[2] = this.rotw(blk[2],1) ^ (a+b+this.tfsKey[4*i+10])&this.wMax;
    blk[3] = this.rotw( blk[3]^(a+2*b+this.tfsKey[4*i+11])&this.wMax, 31 );
    a=this.G0(blk[2]);
    b=this.G1(blk[3]);
    blk[0] = this.rotw(blk[0],1) ^ (a+b+this.tfsKey[4*i+8])&this.wMax;
    blk[1] = this.rotw( blk[1]^(a+2*b+this.tfsKey[4*i+9])&this.wMax, 31 );
  }

  pidCrypt.Twofish.prototype.close = function()
  {
    this.tfsKey=[];
    this.tfsM=[[],[],[],[]];
  }

  pidCrypt.Twofish.prototype.encrypt = function(bData)
  {
    var blk=[this.getW(bData,0)^this.tfsKey[0], this.getW(bData,4)^this.tfsKey[1], this.getW(bData,8)^this.tfsKey[2], this.getW(bData,12)^this.tfsKey[3]];
    for (var j=0;j<8;j++)
    {
      this.frnd(j,blk);
    }
    this.setW(bData,0,blk[2]^this.tfsKey[4]);
    this.setW(bData,4,blk[3]^this.tfsKey[5]);
    this.setW(bData,8,blk[0]^this.tfsKey[6]);
    this.setW(bData,12,blk[1]^this.tfsKey[7]);
    return bData;
  }

  pidCrypt.Twofish.prototype.decrypt = function(bData)
  {
    var blk=[this.getW(bData,0)^this.tfsKey[4], this.getW(bData,4)^this.tfsKey[5], this.getW(bData,8)^this.tfsKey[6], this.getW(bData,12)^this.tfsKey[7]];
    for (var j=7;j>=0;j--)
    {
      this.irnd(j,blk);
    }
    this.setW(bData,0,blk[2]^this.tfsKey[0]);
    this.setW(bData,4,blk[3]^this.tfsKey[1]);
    this.setW(bData,8,blk[0]^this.tfsKey[2]);
    this.setW(bData,12,blk[1]^this.tfsKey[3]);
    return bData;
  }

}

