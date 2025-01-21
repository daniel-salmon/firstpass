# firstpass

firstpass is a command line utility that helps you manage your secrets, similar
to 1Password and LastPass. It supports the ability to store your secrets
locally or in the cloud.

# Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
  - [Getting started](#getting-started)
  - [Customizing your profile](#customizing-your-profile)
  - [Creating a vault](#creating-a-vault)
  - [Managing your vault](#managing-your-vault)
  - [Managing multiple configs](#managing-multiple-configs)

## Overview <a name="overview"></a>

firstpass allows you to manage your secrets locally and via the cloud. When you
store your secrets in the cloud, your secrets are stored via zero-knowledge
encryption: only your password-encrypted secrets leave your computer and your
plaintext secrets and password never do. By storing your secrets in the cloud,
you can access them from any computer. You can deploy your own backend for
managing your secrets by referring to
[firstpass-backend](https://github.com/daniel-salmon/firstpass-backend) which
is an open source implementation of the secrets manager that is also deployed
and ready to use by this utility as-is. That is, if you use this utility and
you choose to store some secrets in the cloud, by default it will store them in
a backend that is currently deployed on Heroku. But if you would like more
control, you can manage your own deployment by consulting
[firstpass-backend](https://github.com/daniel-salmon/firstpass-backend).

If you store your secrets locally, you can store them in an unlimited number of
files which are encrypted at-rest on disk. You can move those files anywhere
and access them again using the firstpass CLI.

You can store different secrets via different means. Syncing between local and
cloud is not currently supported, but eventually I would like to add that
feature. However, you might have some secrets stored in one encrypted file,
other secrets in a different file, and some stored in the cloud. You can change
the profile to use at the CLI when interacting with your secrets vault.

## Installation <a name="installation"></a>

You can install this project using your Python environment or package manager
directly from this GitHub repo. For example if you use `uv`:

```sh
# uv
$ uv add git+https://github.com/daniel-salmon/firstpass
```

## Usage <a name="usage"></a>

firstpass exposes a CLI through which you can manage your secrets. It uses a
`config` to manage your settings, and the CLI lets you manage your `config`. A
`config` details settings for your profile. You can have multiple `config`s,
but the default `config` on your computer will live at
`$HOME/.config/firstpass/config.yaml`. After setting up your `config`, which
will dictate if you use firstpass for managing local or cloud secrets, you can
interact with your secrets via the CLI. In particular, you can add, update or
delete your secrets. You can also fetch your secrets and, optionally, copy them
to your clipboard!

### Getting started <a name="getting-started"></a>

To get started you will need to initialize your configuration by creating a new
`config`:

```sh
$ firstpass init config
```
This will create a new `config` at `$HOME/.config/firstpass/config.yaml` and will contain details on:

* If you are storing your secrets locally or in the cloud.
* The backend URL for storing your secrets, if you do chose to store your secrets in the cloud.
* Your username (only important for cloud storage).
* The file path of your encrypted secrets (only important for local storage).

### Customizing your profile <a name="customizing-your-profile"></a>

To customize your profile, you need to update your `config`. The CLI lets you
do that via the `config` group of commands:

```sh
$ firstpass config --help

 Usage: firstpass config [OPTIONS] COMMAND [ARGS]...

 Manage a config.

Options
 --config-path        PATH  Path to config [default: None]
 --help                     Show this message and exit.

Commands
 list-keys   List options available to customize in your config.
 get         Get an option from your config.
 set         Set an option in your config.
```

You can chose to make your vault local by setting the option `local=True` like
so

```sh
$ firstpass config set local True
```

If you deploy the backend yourself, you can update the `cloud_host` option to
be the URL of your backend.

### Creating a vault <a name="creating-a-vault"></a>

Creating a new vault will be different depending on if you plan to manage your
secrets locally or via the cloud. For local management, creating a new vault is
simple:

```sh
$ firstpass vault init
```

You will be prompted to enter (and re-enter) a password that will be used to
encrypt your vault file.

If you plan to manage your secrets in the cloud you will first need to make
sure the `username` option you have set in your config is what you want your
username to be. Once you choose that `username` you cannot change it (although
you can always make a new profile by creating a new `config`) and your choice
must be unique across all users who store their secrets in the cloud.

After making sure your `username` is what you want you can then run

```sh
$ firstpass vault init
```

You will be prompted to confirm the `username` is what you want it to be; if it
isn't you should update your `config`. It will also ask you to enter (and
re-enter) a password that will be used to authenticate you and encrypt your
secrets.

### Managing your vault <a name="managing-your-vault"></a>

The CLI exposes some CRUD functionality for managing your secrets.

```sh
$ uv run firstpass vault --help

 Usage: firstpass vault [OPTIONS] COMMAND [ARGS]...

 Manage your vault.

 Options
 --config-path        PATH  Path to config [default: None]
 --help                     Show this message and exit.

 Commands
 list-parts   List the parts of the given type of secret.
 init         Initialize a new vault.
 remove       Remove your vault.
 new          Create a new secret / entry for your vault.
 list-names   List the names of all of your secrets.
 get          Get a secret by name from your vault.
 set          Set the value for a secret.
 delete       Delete a secret from your vault.
```

Although at the moment firstpass only supports `Password` types of secrets, the
intention is to support other types of secrets (e.g., `Note`s) in the future.
Therefore, when you interact with your vault you must specify the type of
secret you want to interact with. With each secret type, secrets are uniquely
identified by a `name`. You can list the `name`s of all secrets you have by
calling `list-names`.

Here is an example of a workflow you might have to create a new password entry
in your vault. Suppose you have a password you want to make related to pizza
toppings. You might do

```sh
$ firstpass vault new passwords
Password: # You will be prompted to enter the password to unlock your vault
Let's create a new vault entry for passwords
What's the name of this entry: pickles
Enter the password: # Enter what your password should be for this entry
Re-enter the password: # Re-enter the password
Enter the label: pizza topings # Enter any labels you want for this secret
Enter the notes: disgusting # Enter any notes you want to attach
Enter the username: pepperoni # Enter the username for this secret
```

You will now have a new passwords-type vault entry. If you want to manage this
entry, use the `name` "pickles" to refer to it. For instance, to list all
elements of the secret you might do

```sh
$ firstpass vault get passwords pickles all
Password: # You will be prompted to enter the password to unlock your vault
label='pizza toppings' notes='disgusting' username='username' password=SecretStr('**********')
```

Note that your password itself will not be shown. If you'd like to copy to your
clipboard:

```sh
$ firstpass vault get passwords pickles password --copy
Password: # You will be prompted to enter the password to unlock your vault
**********
```

If you had wanted to show your password on standard out, you could specify
`--show` as an option to `get`.

### Managing multiple `config`s <a name="managing-multiple-configs"></a>

As mentioned earlier, you can keep multiple profiles for keeping secrets
separated. When you want to use a non-default profile you must pass the
`--config-path` option to your command. This should be a path to a valid
`config` file (which you can generate with a call to `init config`). For
example, if you want to use a non-default config located at
`$HOME/non/default/config.yaml` you might do

```sh
$ firstpass vault --config-path $HOME/non/default/config.yaml get passwords pickles all
```

You can have any number of configs, provided they live in distinct files on
your filesystem.
