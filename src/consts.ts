import type { IconMap, SocialLink, Site } from '@/types'

export const SITE: Site = {
  title: 'Archan6el',
  description:
    'Welcome to my blog! You\'ll find my write ups, among other things, here',
  href: 'https://astro-erudite.vercel.app',
  author: 'Archan6el',
  locale: 'en-US',
  featuredPostCount: 3,
  postsPerPage: 3,
}

export const NAV_LINKS: SocialLink[] = [
  {
    href: '/blog',
    label: 'blog',
  },
  {
    href: '/authors',
    label: 'author',
  },
  {
    href: '/tags',
    label: 'tags'
  },
  /*{
    href: '/about',
    label: 'about',
  },*/
]

export const SOCIAL_LINKS: SocialLink[] = [
  {
    href: 'https://github.com/Archan6el',
    label: 'GitHub',
  },
  /*{
    href: 'https://twitter.com/enscry',
    label: 'Twitter',
  },*/
  {
    href: 'mailto:myk0675@gmail.com',
    label: 'Email',
  },
  {
    href: 'https://www.linkedin.com/in/michael-ace-bengil-83a535212/',
    label: 'LinkedIn',
  },
  /*{
    href: '/rss.xml',
    label: 'RSS',
  },*/
]

export const ICON_MAP: IconMap = {
  Website: 'lucide:globe',
  GitHub: 'lucide:github',
  LinkedIn: 'lucide:linkedin',
  Twitter: 'lucide:twitter',
  Email: 'lucide:mail',
  RSS: 'lucide:rss',
}
