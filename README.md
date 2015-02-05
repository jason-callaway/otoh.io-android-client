# otoh.io Android Client

Android client for otoh.io social key management.  Learn more at https://otoh.io.

This is tricky to build right now.  It should get easier in the next few days.  Check back soon, or email jason@otoh.io if you can't wait.

# Library requirements

You'll need some jars from [Spongy Castle](http://rtyley.github.io/spongycastle/), which is a variant of [Bouncy Castle](http://www.bouncycastle.org/java.html).

Grab the latest versions of core, prov, pkix, and pg.

Also, you'll need android-support-v4.jar.

# Build Procedure
(Note: the build procedure section is under development. Email jason@otoh.io if you're having trouble building.)

1.  Create a new [Android Studio](http://developer.android.com/tools/studio/index.html) project named otoh.io. Specify the company name as otoh.io as well.
2.  Clone the repository into the AndroidStudioProjects directory. Don't forget to checkout the branch you want to work on.
[code]cd ~/AndroidStudioProjects/otoh.io
git clone https://github.com/otohdotio/android.git
git checkout interesting_branch[/code]
3.  Copy the files to the right location.
[code]cd android; cp -Rp app ..
4.  Rename the repo to something useful to you, like:
[code]mv android otoh.io[/code]
5.  Download the [Spongy Castle](http://rtyley.github.io/spongycastle/) jars
[code]cd otoh.io/app/libs
wget http://search.maven.org/remotecontent?filepath=com/madgag/spongycastle/core/1.51.0.0/core-1.51.0.0.jar
wget http://search.maven.org/remotecontent?filepath=com/madgag/spongycastle/prov/1.51.0.0/prov-1.51.0.0.jar
wget http://search.maven.org/remotecontent?filepath=com/madgag/spongycastle/pkix/1.51.0.0/pkix-1.51.0.0.jar
wget http://search.maven.org/remotecontent?filepath=com/madgag/spongycastle/pg/1.51.0.0/pg-1.51.0.0.jar
[/code]
6.  #compatibility jar
7.  Gradle sync
