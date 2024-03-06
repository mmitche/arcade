# The Unified Build Almanac (TUBA) - VMR Build Guide

## Purpose

This document is intended to document:
- How a VMR build works
- How a repository component that participates in Unified Build interfaces with it. This includes the interface defining how a component build is invoked, as well as dependency flow. It is intended to answer the question: If I participate in VMR builds, how will build of my component work?

## Background Context

When .NET is built from the VMR, it's built as a series of "verticals" from a single source repository. A vertical is a series of a component (e.g. arcade and runtime and sdk) builds that are needed to produce a set of artifacts for that vertical. Verticals are generally defined by a runtime 'flavor' and other assets closely associated with that flavor. Examples include:
- A 'tall' Windows x64 vertical producing a full .NET SDK build with the CoreCLR runtime targeted at win-x64.
- A 'short' stack (producing only a runtime pack) representing iOS AOT for x64.

After completion of the initial set of vertical builds, additional passes over the same verticals may be run, using the outputs from previous passes as inputs. This allows for creation of artifacts that require a 'join', or inputs from multiple verticals. For more information on the join point infra, please see (TODO: FUTURE DOC LINK HERE).

## Build Overview

A build of the VMR is invoked via the build.sh or build.cmd script at the root of the https://github.com/dotnet/dotnet repository. This script invokes the VMR root build project (https://github.com/dotnet/dotnet/blob/main/build.proj) with basic parameters identifying key properties of the build. E.g. binlog locations, target architecture, source-only vs. more than source-allowed, etc. The root build project then runs series of initialization tasks, then invokes a build of the "root repository" project. This root repository project is the component that the particular invocation is trying to build. Short stacks build [runtime](https://github.com/dotnet/dotnet/blob/main/repo-projects/runtime.proj), and full SDK stacks build [dotnet](https://github.com/dotnet/dotnet/blob/main/repo-projects/dotnet.proj), which roughly corresponds to the sdk component. All repositories that make up the .NET project and are part of the VMR have a corresponding repository project. For example, [dotnet/sdk](https://github.com/dotnet/sdk) corresponds to [sdk.proj](https://github.com/dotnet/dotnet/blob/main/repo-projects/sdk.proj), [arcade](https://github.com/dotnet/arcade) to [arcade.proj](https://github.com/dotnet/dotnet/blob/main/repo-projects/arcade.proj), etc.

When building any component project in the VMR we first need to build its dependencies. These dependencies are identified in the repository project, and the automation simply invokes the builds of those projects before continuing with the current project. Those dependencies may have their own dependencies, and so those get built before continuing, etc. Once a project is reached that has no dependencies (e.g. arcade in non-source-only modes), the repo build is invoked.

The repository build is the simply the invocation of a specified build script with a set of parameters. By default the build script is the arcade standard `eng/common/build.ps1` with -restore -build -pack -publish and a set of arguments. Examples incldude: debug vs. release, whether tests should be built, or if the build is source-only. In addition to the basic set of arguments, a set of flags that identify the build as being invoked by the "orchestrator" and being in "VMR mode". See [Unified Build Controls](./Unified-Build-Controls.md) for more info. Repository projects also have the option of customizing the input parameters or build script. This is typcial for repositories with more complex automation, like runtime or aspnetcore.



## Build Details

### Layers

### Phases

### Repository Interface Overview

### Repository Build Details

