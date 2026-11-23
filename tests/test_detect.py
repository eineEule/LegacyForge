from legacyforge import detect
from legacyforge.recipe import parse

LIBRARY_VDF = r'''
"libraryfolders"
{
    "0"
    {
        "path"      "%s"
        "apps" { "287450" "123" }
    }
}
'''

ACF = '''
"AppState"
{
    "appid"       "287450"
    "installdir"  "Rise of Nations"
}
'''


def test_parse_vdf_nested():
    data = detect.parse_vdf('"a" { "b" "c" "d" { "e" "f" } }')
    assert data == {"a": {"b": "c", "d": {"e": "f"}}}


def test_finds_steam_game(tmp_path):
    steam = tmp_path / "Steam"
    game = steam / "steamapps" / "common" / "Rise of Nations"
    game.mkdir(parents=True)
    (game / "riseofnations.exe").write_bytes(b"MZ")
    (steam / "steamapps" / "libraryfolders.vdf").write_text(
        LIBRARY_VDF % str(steam).replace("\\", "\\\\")
    )
    (steam / "steamapps" / "appmanifest_287450.acf").write_text(ACF)
    libs = detect.steam_libraries(steam)
    r = parse({"game": "ron", "name": "RoN", "detect": {"steam_appid": 287450, "exe": "riseofnations.exe"}, "fixes": []})
    assert detect.locate(r, libs) == game
