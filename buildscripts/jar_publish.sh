#!/bin/bash

if [ "$TRAVIS_REPO_SLUG" == "demandware-appsec/Content-Manipulator" ] && [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_BRANCH" == "master" ]; then

  echo -e "Creating jar file"
  mvn -f content-manipulator/pom.xml install

  echo -e "Publishing jar for $TRAVIS_JDK_VERSION"
  jdkver=$(echo -n $TRAVIS_JDK_VERSION | tail -c 4)

  cp content-manipulator/target/*.jar $HOME/jar-latest/content-manipulator.jar
  echo -e "Copied jar"

  cd $HOME
  git config --global user.email "travis@travis-ci.org"
  git config --global user.name "travis-ci"
  git clone --quiet --branch=gh-pages https://${GH_TOKEN}@github.com/demandware-appsec/Content-Manipulator gh-pages > /dev/null
  echo -e "Cloned gh-pages"

  cd gh-pages
  cp $HOME/jar-latest/content-manipulator.jar ./jar/content-manipulator-$jdkver.jar
  git add -f .
  git commit -m "Updating jars on successful travis build $TRAVIS_BUILD_NUMBER auto-pushed to gh-pages"
  git push -fq origin gh-pages > /dev/null
  echo -e "Published Jar to gh-pages.\n"

fi