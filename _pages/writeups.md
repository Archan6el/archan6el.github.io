---
layout: default
---

<h1>Writeups</h1>

{% assign postsByYear = site.writeups | group_by_exp:"post", "post.date | date: '%Y'" %}

{% assign sortedPostsByYear = postsByYear | sort: "name" | reverse %}

{% for year in sortedPostsByYear %}
  {{ year.name }}
  <br>
  <ul style="padding-top: 0.3em;">
    {% assign categories = year.items | group_by:"category" %}
    {% for category in categories %}
      <a href="{{ '/' | absolute_url }}writeups/{{ year.name }}/{{ category.name }}">
        {{ category.name | replace: '-', ' ' }}
      </a>
      <ul style="padding-top: 0.1em;">
        {% for post in category.items %}
          {% assign postCategory = post.title | downcase %}
          {% assign categoryName = category.name | replace: '-', ' ' | downcase %}
          {% if categoryName != postCategory %}
            <li style="line-height: 1; padding-top: 0.4em;">
              <a href="{{ post.url | absolute_url }}"> {{ post.title }}</a>
              <br>
              <small>[{{ post.points }}]</small>
              <span class="tag">
                <small>
                  &lt;{{ post.tags | join: '/&gt; &lt;' }}/&gt;
                </small>
              </span>
            </li>
          {% endif %}
        {% endfor %}
      </ul>
      <br>
    {% endfor %}
  </ul>
{% endfor %}
